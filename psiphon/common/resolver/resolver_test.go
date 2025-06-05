/*
 * Copyright (c) 2022, Psiphon Inc.
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

package resolver

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/transforms"
	"github.com/miekg/dns"
)

func TestMakeResolveParameters(t *testing.T) {
	err := runTestMakeResolveParameters()
	if err != nil {
		t.Fatal(errors.Trace(err).Error())
	}
}

func TestResolver(t *testing.T) {
	err := runTestResolver()
	if err != nil {
		t.Fatal(errors.Trace(err).Error())
	}
}

func TestPublicDNSServers(t *testing.T) {
	IPs, metrics, err := runTestPublicDNSServers()
	if err != nil {
		t.Fatal(errors.Trace(err).Error())
	}
	t.Logf("IPs: %v", IPs)
	t.Logf("Metrics: %v", metrics)
}

func runTestMakeResolveParameters() error {

	frontingProviderID := "frontingProvider"
	frontingDialDomain := exampleDomain
	alternateDNSServer := "172.16.0.1"
	alternateDNSServerWithPort := net.JoinHostPort(alternateDNSServer, resolverDNSPort)
	preferredAlternateDNSServer := "172.16.0.2"
	preferredAlternateDNSServerWithPort := net.JoinHostPort(preferredAlternateDNSServer, resolverDNSPort)
	transformName := "exampleTransform"

	paramValues := map[string]interface{}{
		"DNSResolverAttemptsPerServer":                2,
		"DNSResolverAttemptsPerPreferredServer":       1,
		"DNSResolverPreresolvedIPAddressProbability":  1.0,
		"DNSResolverPreresolvedIPAddressCIDRs":        parameters.LabeledCIDRs{frontingProviderID: []string{exampleIPv4CIDR}},
		"DNSResolverAlternateServers":                 []string{alternateDNSServer},
		"DNSResolverPreferredAlternateServers":        []string{preferredAlternateDNSServer},
		"DNSResolverPreferAlternateServerProbability": 1.0,
		"DNSResolverProtocolTransformProbability":     1.0,
		"DNSResolverProtocolTransformSpecs":           transforms.Specs{transformName: exampleTransform},
		"DNSResolverProtocolTransformScopedSpecNames": transforms.ScopedSpecNames{preferredAlternateDNSServer: []string{transformName}},
		"DNSResolverQNameRandomizeCasingProbability":  1.0,
		"DNSResolverQNameMustMatchProbability":        1.0,
		"DNSResolverIncludeEDNS0Probability":          1.0,
	}

	params, err := parameters.NewParameters(nil)
	if err != nil {
		return errors.Trace(err)
	}
	_, err = params.Set("", 0, paramValues)
	if err != nil {
		return errors.Trace(err)
	}

	resolver := NewResolver(&NetworkConfig{}, "")
	defer resolver.Stop()

	resolverParams, err := resolver.MakeResolveParameters(
		params.Get(), frontingProviderID, frontingDialDomain)
	if err != nil {
		return errors.Trace(err)
	}

	// Test: PreresolvedIPAddress

	CIDRContainsIP := func(CIDR, IP string) bool {
		_, IPNet, _ := net.ParseCIDR(CIDR)
		return IPNet.Contains(net.ParseIP(IP))
	}

	if resolverParams.AttemptsPerServer != 2 ||
		resolverParams.AttemptsPerPreferredServer != 1 ||
		resolverParams.RequestTimeout != 5*time.Second ||
		resolverParams.AwaitTimeout != 10*time.Millisecond ||
		!CIDRContainsIP(exampleIPv4CIDR, resolverParams.PreresolvedIPAddress) ||
		resolverParams.PreresolvedDomain != frontingDialDomain {
		return errors.Tracef("unexpected resolver parameters: %+v", resolverParams)
	}

	// Test: additional generateIPAddressFromCIDR cases

	for i := 0; i < 10000; i++ {
		for _, CIDR := range []string{exampleIPv4CIDR, exampleIPv6CIDR} {
			IP, err := generateIPAddressFromCIDR(CIDR)
			if err != nil {
				return errors.Trace(err)
			}
			if !CIDRContainsIP(CIDR, IP.String()) || common.IsBogon(IP) {
				return errors.Tracef(
					"invalid generated IP address %v for CIDR %v", IP, CIDR)
			}
		}
	}

	// Test: Preferred/Transform/RandomQNameCasing/QNameMustMatch/EDNS(0)

	paramValues["DNSResolverPreresolvedIPAddressProbability"] = 0.0

	_, err = params.Set("", 0, paramValues)
	if err != nil {
		return errors.Trace(err)
	}

	resolverParams, err = resolver.MakeResolveParameters(
		params.Get(), frontingProviderID, frontingDialDomain)
	if err != nil {
		return errors.Trace(err)
	}

	if resolverParams.AttemptsPerServer != 2 ||
		resolverParams.AttemptsPerPreferredServer != 1 ||
		resolverParams.RequestTimeout != 5*time.Second ||
		resolverParams.AwaitTimeout != 10*time.Millisecond ||
		resolverParams.PreresolvedIPAddress != "" ||
		resolverParams.PreresolvedDomain != "" ||
		resolverParams.AlternateDNSServer != preferredAlternateDNSServerWithPort ||
		resolverParams.PreferAlternateDNSServer != true ||
		resolverParams.ProtocolTransformName != transformName ||
		resolverParams.ProtocolTransformSpec == nil ||
		resolverParams.RandomQNameCasingSeed == nil ||
		resolverParams.ResponseQNameMustMatch != true ||
		resolverParams.IncludeEDNS0 != true {
		return errors.Tracef("unexpected resolver parameters: %+v", resolverParams)
	}

	// Test: No Preferred/Transform/EDNS(0)

	paramValues["DNSResolverPreferAlternateServerProbability"] = 0.0
	paramValues["DNSResolverProtocolTransformProbability"] = 0.0
	paramValues["DNSResolverQNameRandomizeCasingProbability"] = 0.0
	paramValues["DNSResolverQNameMustMatchProbability"] = 0.0
	paramValues["DNSResolverIncludeEDNS0Probability"] = 0.0

	_, err = params.Set("", 0, paramValues)
	if err != nil {
		return errors.Trace(err)
	}

	resolverParams, err = resolver.MakeResolveParameters(
		params.Get(), frontingProviderID, frontingDialDomain)
	if err != nil {
		return errors.Trace(err)
	}

	if resolverParams.AttemptsPerServer != 2 ||
		resolverParams.AttemptsPerPreferredServer != 1 ||
		resolverParams.RequestTimeout != 5*time.Second ||
		resolverParams.AwaitTimeout != 10*time.Millisecond ||
		resolverParams.PreresolvedIPAddress != "" ||
		resolverParams.PreresolvedDomain != "" ||
		resolverParams.AlternateDNSServer != alternateDNSServerWithPort ||
		resolverParams.PreferAlternateDNSServer != false ||
		resolverParams.ProtocolTransformName != "" ||
		resolverParams.ProtocolTransformSpec != nil ||
		resolverParams.RandomQNameCasingSeed != nil ||
		resolverParams.ResponseQNameMustMatch != false ||
		resolverParams.IncludeEDNS0 != false {
		return errors.Tracef("unexpected resolver parameters: %+v", resolverParams)
	}

	return nil
}

func runTestResolver() error {

	// noResponseServer will not respond to requests
	noResponseServer, err := newTestDNSServer(false, false, false, false)
	if err != nil {
		return errors.Trace(err)
	}
	defer noResponseServer.stop()

	// invalidIPServer will respond with an invalid IP
	invalidIPServer, err := newTestDNSServer(true, false, false, false)
	if err != nil {
		return errors.Trace(err)
	}
	defer invalidIPServer.stop()

	// okServer will respond to correct requests (expected domain) with the
	// correct response (expected IPv4 or IPv6 address)
	okServer, err := newTestDNSServer(true, true, false, false)
	if err != nil {
		return errors.Trace(err)
	}
	defer okServer.stop()

	// alternateOkServer behaves like okServer; getRequestCount is used to
	// confirm that the alternate server was indeed used
	alternateOkServer, err := newTestDNSServer(true, true, false, false)
	if err != nil {
		return errors.Trace(err)
	}
	defer alternateOkServer.stop()

	// transformOkServer behaves like okServer but only responds if the
	// transform was applied; other servers do not respond if the transform
	// is applied
	transformOkServer, err := newTestDNSServer(true, true, true, false)
	if err != nil {
		return errors.Trace(err)
	}
	defer transformOkServer.stop()

	randomQNameCasingOkServer, err := newTestDNSServer(true, true, false, true)
	if err != nil {
		return errors.Trace(err)
	}
	defer randomQNameCasingOkServer.stop()

	servers := []string{noResponseServer.getAddr(), invalidIPServer.getAddr(), okServer.getAddr()}

	networkConfig := &NetworkConfig{
		GetDNSServers: func() []string { return servers },
		LogWarning:    func(err error) { fmt.Printf("LogWarning: %v\n", err) },
	}

	networkID := "networkID-1"

	resolver := NewResolver(networkConfig, networkID)
	defer resolver.Stop()

	params := &ResolveParameters{
		AttemptsPerServer:          1,
		AttemptsPerPreferredServer: 1,
		RequestTimeout:             250 * time.Millisecond,
		AwaitTimeout:               250 * time.Millisecond,
		IncludeEDNS0:               true,
	}

	checkResult := func(IPs []net.IP) error {
		var IPv4, IPv6 net.IP
		for _, IP := range IPs {
			if IP.To4() != nil {
				IPv4 = IP
			} else {
				IPv6 = IP
			}
		}
		if IPv4 == nil {
			return errors.TraceNew("missing IPv4 response")
		}
		if IPv4.String() != exampleIPv4 {
			return errors.TraceNew("unexpected IPv4 response")
		}
		if resolver.hasIPv6Route {
			if IPv6 == nil {
				return errors.TraceNew("missing IPv6 response")
			}
			if IPv6.String() != exampleIPv6 {
				return errors.TraceNew("unexpected IPv6 response")
			}
		}
		return nil
	}

	ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelFunc()

	// Test: should retry until okServer responds

	IPs, err := resolver.ResolveIP(ctx, networkID, params, exampleDomain)
	if err != nil {
		return errors.Trace(err)
	}

	err = checkResult(IPs)
	if err != nil {
		return errors.Trace(err)
	}

	if resolver.metrics.resolves != 1 ||
		resolver.metrics.cacheHits != 0 ||
		resolver.metrics.requestsIPv4 != 3 || resolver.metrics.responsesIPv4 != 1 ||
		(resolver.hasIPv6Route && (resolver.metrics.requestsIPv6 != 3 || resolver.metrics.responsesIPv6 != 1)) {
		return errors.Tracef("unexpected metrics: %+v", resolver.metrics)
	}

	// Test: cached response

	beforeMetrics := resolver.metrics

	IPs, err = resolver.ResolveIP(ctx, networkID, params, exampleDomain)
	if err != nil {
		return errors.Trace(err)
	}

	err = checkResult(IPs)
	if err != nil {
		return errors.Trace(err)
	}

	if resolver.metrics.resolves != beforeMetrics.resolves+1 ||
		resolver.metrics.cacheHits != beforeMetrics.cacheHits+1 ||
		resolver.metrics.requestsIPv4 != beforeMetrics.requestsIPv4 ||
		resolver.metrics.requestsIPv6 != beforeMetrics.requestsIPv6 {
		return errors.Tracef("unexpected metrics: %+v", resolver.metrics)
	}

	// Test: PreresolvedIPAddress

	beforeMetrics = resolver.metrics

	params.PreresolvedIPAddress = exampleIPv4
	params.PreresolvedDomain = exampleDomain

	IPs, err = resolver.ResolveIP(ctx, networkID, params, exampleDomain)
	if err != nil {
		return errors.Trace(err)
	}

	if len(IPs) != 1 || IPs[0].String() != exampleIPv4 {
		return errors.TraceNew("unexpected preresolved response")
	}

	if resolver.metrics.resolves != beforeMetrics.resolves+1 ||
		resolver.metrics.cacheHits != beforeMetrics.cacheHits ||
		resolver.metrics.requestsIPv4 != beforeMetrics.requestsIPv4 ||
		resolver.metrics.requestsIPv6 != beforeMetrics.requestsIPv6 {
		return errors.Tracef("unexpected metrics: %+v", resolver.metrics)
	}

	params.PreresolvedIPAddress = ""

	// Test: PreresolvedIPAddress set for different domain

	beforeMetrics = resolver.metrics

	params.PreresolvedIPAddress = exampleIPv4
	params.PreresolvedDomain = "not.example.com"

	IPs, err = resolver.ResolveIP(ctx, networkID, params, exampleDomain)
	if err != nil {
		return errors.Trace(err)
	}

	err = checkResult(IPs)
	if err != nil {
		return errors.Trace(err)
	}

	if resolver.metrics.resolves != beforeMetrics.resolves+1 ||
		resolver.metrics.cacheHits != beforeMetrics.cacheHits+1 ||
		resolver.metrics.requestsIPv4 != beforeMetrics.requestsIPv4 ||
		resolver.metrics.requestsIPv6 != beforeMetrics.requestsIPv6 {
		return errors.Tracef("unexpected metrics: %+v", resolver.metrics)
	}

	params.PreresolvedIPAddress = ""
	params.PreresolvedDomain = ""

	// Test: change network ID, which must clear cache

	beforeMetrics = resolver.metrics

	networkID = "networkID-2"

	IPs, err = resolver.ResolveIP(ctx, networkID, params, exampleDomain)
	if err != nil {
		return errors.Trace(err)
	}

	err = checkResult(IPs)
	if err != nil {
		return errors.Trace(err)
	}

	if resolver.metrics.resolves != beforeMetrics.resolves+1 ||
		resolver.metrics.cacheHits != beforeMetrics.cacheHits {
		return errors.Tracef("unexpected metrics: %+v (%+v)", resolver.metrics, beforeMetrics)
	}

	// Test: PreferAlternateDNSServer

	if alternateOkServer.getRequestCount() != 0 {
		return errors.TraceNew("unexpected alternate server request count")
	}

	resolver.cache.Flush()

	params.AlternateDNSServer = alternateOkServer.getAddr()
	params.PreferAlternateDNSServer = true

	IPs, err = resolver.ResolveIP(ctx, networkID, params, exampleDomain)
	if err != nil {
		return errors.Trace(err)
	}

	err = checkResult(IPs)
	if err != nil {
		return errors.Trace(err)
	}

	if alternateOkServer.getRequestCount() < 1 {
		return errors.TraceNew("unexpected alternate server request count")
	}

	params.AlternateDNSServer = ""
	params.PreferAlternateDNSServer = false

	// Test: PreferAlternateDNSServer with failed attempt (exercise maxAttempts prefer case)

	resolver.cache.Flush()

	params.AlternateDNSServer = invalidIPServer.getAddr()
	params.PreferAlternateDNSServer = true

	IPs, err = resolver.ResolveIP(ctx, networkID, params, exampleDomain)
	if err != nil {
		return errors.Trace(err)
	}

	err = checkResult(IPs)
	if err != nil {
		return errors.Trace(err)
	}

	params.AlternateDNSServer = ""
	params.PreferAlternateDNSServer = false

	// Test: fall over to AlternateDNSServer when no system servers

	beforeCount := alternateOkServer.getRequestCount()

	previousGetDNSServers := networkConfig.GetDNSServers

	networkConfig.GetDNSServers = func() []string { return nil }

	// Force system servers update
	networkID = "networkID-3"

	resolver.cache.Flush()

	params.AlternateDNSServer = alternateOkServer.getAddr()
	params.PreferAlternateDNSServer = false

	IPs, err = resolver.ResolveIP(ctx, networkID, params, exampleDomain)
	if err != nil {
		return errors.Trace(err)
	}

	err = checkResult(IPs)
	if err != nil {
		return errors.Trace(err)
	}

	if alternateOkServer.getRequestCount() <= beforeCount {
		return errors.TraceNew("unexpected alterate server request count")
	}

	// Test: use default, standard resolver when no servers

	resolver.cache.Flush()

	params.AlternateDNSServer = ""
	params.PreferAlternateDNSServer = false

	if len(resolver.systemServers) != 0 {
		return errors.TraceNew("unexpected server count")
	}

	IPs, err = resolver.ResolveIP(ctx, networkID, params, exampleRealDomain)
	if err != nil {
		return errors.Trace(err)
	}

	if len(IPs) == 0 {
		return errors.TraceNew("unexpected response")
	}

	// Test: ResolveAddress

	networkConfig.GetDNSServers = previousGetDNSServers

	// Force system servers update
	networkID = "networkID-4"

	domainAddress := net.JoinHostPort(exampleDomain, "443")

	address, err := resolver.ResolveAddress(ctx, networkID, params, "", domainAddress)
	if err != nil {
		return errors.Trace(err)
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return errors.Trace(err)
	}

	IP := net.ParseIP(host)

	if IP == nil || (host != exampleIPv4 && host != exampleIPv6) || port != "443" {
		return errors.TraceNew("unexpected response")
	}

	// Test: protocol transform

	if transformOkServer.getRequestCount() != 0 {
		return errors.TraceNew("unexpected transform server request count")
	}

	resolver.cache.Flush()

	params.AttemptsPerServer = 0
	params.AlternateDNSServer = transformOkServer.getAddr()
	params.PreferAlternateDNSServer = true

	seed, err := prng.NewSeed()
	if err != nil {
		return errors.Trace(err)
	}

	params.ProtocolTransformName = "exampleTransform"
	params.ProtocolTransformSpec = exampleTransform
	params.ProtocolTransformSeed = seed

	IPs, err = resolver.ResolveIP(ctx, networkID, params, exampleDomain)
	if err != nil {
		return errors.Trace(err)
	}

	err = checkResult(IPs)
	if err != nil {
		return errors.Trace(err)
	}

	if transformOkServer.getRequestCount() < 1 {
		return errors.TraceNew("unexpected transform server request count")
	}

	params.AttemptsPerServer = 1
	params.AlternateDNSServer = ""
	params.PreferAlternateDNSServer = false
	params.ProtocolTransformName = ""
	params.ProtocolTransformSpec = nil
	params.ProtocolTransformSeed = nil

	// Test: random QName (hostname) casing
	//
	// Note: there's a (1/2)^N chance that the QName (hostname) with randomized
	// casing has the same casing as the input QName, where N is the number of
	// Unicode letters in the QName. In such an event these tests will either
	// give a false positive or false negative depending on the subtest.

	if randomQNameCasingOkServer.getRequestCount() != 0 {
		return errors.TraceNew("unexpected random QName casing server request count")
	}

	resolver.cache.Flush()

	params.AttemptsPerServer = 0
	params.AttemptsPerPreferredServer = 1
	params.AlternateDNSServer = randomQNameCasingOkServer.getAddr()
	params.PreferAlternateDNSServer = true
	params.RandomQNameCasingSeed = seed

	_, err = resolver.ResolveIP(ctx, networkID, params, exampleDomain)
	if err != nil {
		return errors.Trace(err)
	}

	resolver.cache.Flush()
	params.ResponseQNameMustMatch = true

	_, err = resolver.ResolveIP(ctx, networkID, params, exampleDomain)
	if err == nil {
		return errors.TraceNew("expected QName mismatch")
	}

	resolver.cache.Flush()
	params.AlternateDNSServer = okServer.getAddr()

	_, err = resolver.ResolveIP(ctx, networkID, params, exampleDomain)
	if err == nil {
		return errors.TraceNew("expected server to not support random QName casing")
	}

	err = checkResult(IPs)
	if err != nil {
		return errors.Trace(err)
	}

	if randomQNameCasingOkServer.getRequestCount() < 1 {
		return errors.TraceNew("unexpected random QName casing server request count")
	}

	params.AttemptsPerServer = 1
	params.AlternateDNSServer = ""
	params.PreferAlternateDNSServer = false
	params.RandomQNameCasingSeed = nil

	// Test: EDNS(0)

	resolver.cache.Flush()

	params.IncludeEDNS0 = true

	IPs, err = resolver.ResolveIP(ctx, networkID, params, exampleDomain)
	if err != nil {
		return errors.Trace(err)
	}

	err = checkResult(IPs)
	if err != nil {
		return errors.Trace(err)
	}

	params.IncludeEDNS0 = false

	// Test: input IP address

	beforeMetrics = resolver.metrics

	resolver.cache.Flush()

	IPs, err = resolver.ResolveIP(ctx, networkID, params, exampleIPv4)
	if err != nil {
		return errors.Trace(err)
	}

	if len(IPs) != 1 || IPs[0].String() != exampleIPv4 {
		return errors.TraceNew("unexpected IPv4 response")
	}

	if resolver.metrics.resolves != beforeMetrics.resolves {
		return errors.Tracef("unexpected metrics: %+v", resolver.metrics)
	}

	// Test: DNS cache extension

	resolver.cache.Flush()

	networkConfig.CacheExtensionInitialTTL = (exampleTTLSeconds * 2) * time.Second
	networkConfig.CacheExtensionVerifiedTTL = 2 * time.Hour

	now := time.Now()

	IPs, err = resolver.ResolveIP(ctx, networkID, params, exampleDomain)
	if err != nil {
		return errors.Trace(err)
	}

	entry, expiry, ok := resolver.cache.GetWithExpiration(exampleDomain)
	if !ok ||
		!reflect.DeepEqual(entry, IPs) ||
		expiry.Before(now.Add(networkConfig.CacheExtensionInitialTTL)) ||
		expiry.After(now.Add(networkConfig.CacheExtensionVerifiedTTL)) {
		return errors.TraceNew("unexpected CacheExtensionInitialTTL state")
	}

	resolver.VerifyCacheExtension(exampleDomain)

	entry, expiry, ok = resolver.cache.GetWithExpiration(exampleDomain)
	if !ok ||
		!reflect.DeepEqual(entry, IPs) ||
		expiry.Before(now.Add(networkConfig.CacheExtensionVerifiedTTL)) {
		return errors.TraceNew("unexpected CacheExtensionInitialTTL state")
	}

	// Set cache flush condition, which should be ignored
	networkID = "networkID-5"

	resolver.updateNetworkState(networkID)

	entry, expiry, ok = resolver.cache.GetWithExpiration(exampleDomain)
	if !ok ||
		!reflect.DeepEqual(entry, IPs) ||
		expiry.Before(now.Add(networkConfig.CacheExtensionVerifiedTTL)) {
		return errors.TraceNew("unexpected CacheExtensionInitialTTL state")
	}

	// Test: cancel context

	resolver.cache.Flush()

	cancelFunc()

	_, err = resolver.ResolveIP(ctx, networkID, params, exampleDomain)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	// Test: cancel context while resolving

	// This test exercises the additional answers and await cases in
	// ResolveIP. The test is timing dependent, and so imperfect, but this
	// configuration can reproduce panics in those cases before bugs were
	// fixed, where DNS responses need to be received just as the context is
	// cancelled.

	networkConfig.GetDNSServers = func() []string { return []string{okServer.getAddr()} }
	networkID = "networkID-6"

	for i := 0; i < 500; i++ {
		resolver.cache.Flush()

		ctx, cancelFunc := context.WithTimeout(
			context.Background(), time.Duration((i%10+1)*20)*time.Microsecond)
		defer cancelFunc()

		_, _ = resolver.ResolveIP(ctx, networkID, params, exampleDomain)
	}

	return nil
}

func runTestPublicDNSServers() ([]net.IP, string, error) {

	networkConfig := &NetworkConfig{
		GetDNSServers: getPublicDNSServers,
	}

	networkID := "networkID-1"

	resolver := NewResolver(networkConfig, networkID)
	defer resolver.Stop()

	params := &ResolveParameters{
		AttemptsPerServer: 1,
		RequestTimeout:    5 * time.Second,
		AwaitTimeout:      1 * time.Second,
		IncludeEDNS0:      true,
	}

	IPs, err := resolver.ResolveIP(
		context.Background(), networkID, params, exampleRealDomain)
	if err != nil {
		return nil, "", errors.Trace(err)
	}

	gotIPv4 := false
	gotIPv6 := false
	for _, IP := range IPs {
		if IP.To4() != nil {
			gotIPv4 = true
		} else {
			gotIPv6 = true
		}
	}
	if !gotIPv4 {
		return nil, "", errors.TraceNew("missing IPv4 response")
	}
	if !gotIPv6 && resolver.hasIPv6Route {
		return nil, "", errors.TraceNew("missing IPv6 response")
	}

	return IPs, resolver.GetMetrics(), nil
}

func getPublicDNSServers() []string {
	servers := []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}
	shuffledServers := make([]string, len(servers))
	for i, j := range prng.Perm(len(servers)) {
		shuffledServers[i] = servers[j]
	}
	return shuffledServers
}

var exampleDomain = fmt.Sprintf("%s.example.com", prng.Base64String(32))

const (
	exampleRealDomain = "example.com"
	exampleIPv4       = "93.184.216.34"
	exampleIPv4CIDR   = "93.184.216.0/24"
	exampleIPv6       = "2606:2800:220:1:248:1893:25c8:1946"
	exampleIPv6CIDR   = "2606:2800:220::/48"
	exampleTTLSeconds = 60
)

// Set the reserved Z flag
var exampleTransform = transforms.Spec{[2]string{"^([a-f0-9]{4})0100", "\\$\\{1\\}0140"}}

type testDNSServer struct {
	respond                 bool
	validResponse           bool
	expectTransform         bool
	expectRandomQNameCasing bool
	addr                    string
	requestCount            int32
	server                  *dns.Server
}

func newTestDNSServer(respond, validResponse, expectTransform, expectRandomQNameCasing bool) (*testDNSServer, error) {

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		return nil, errors.Trace(err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, errors.Trace(err)
	}

	s := &testDNSServer{
		respond:                 respond,
		validResponse:           validResponse,
		expectTransform:         expectTransform,
		expectRandomQNameCasing: expectRandomQNameCasing,
		addr:                    udpConn.LocalAddr().String(),
	}

	server := &dns.Server{
		PacketConn: udpConn,
		Handler:    s,
	}

	s.server = server

	go server.ActivateAndServe()

	return s, nil
}

func (s *testDNSServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	atomic.AddInt32(&s.requestCount, 1)

	if !s.respond {
		return
	}

	// Check the reserved Z flag
	if s.expectTransform != r.MsgHdr.Zero {
		return
	}

	if len(r.Question) != 1 ||
		(!s.expectRandomQNameCasing &&
			r.Question[0].Name != dns.Fqdn(exampleDomain)) {
		return
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Answer = make([]dns.RR, 1)
	if r.Question[0].Qtype == dns.TypeA {
		IP := net.ParseIP(exampleIPv4)
		if !s.validResponse {
			IP = net.ParseIP("127.0.0.1")
		}
		m.Answer[0] = &dns.A{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    exampleTTLSeconds},
			A: IP,
		}
	} else {
		IP := net.ParseIP(exampleIPv6)
		if !s.validResponse {
			IP = net.ParseIP("::1")
		}
		m.Answer[0] = &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    exampleTTLSeconds},
			AAAA: IP,
		}
	}

	if s.expectRandomQNameCasing {
		// Simulate a server that does not preserve the casing of the QName.
		m.Question[0].Name = dns.Fqdn(exampleDomain)
	}

	w.WriteMsg(m)
}

func (s *testDNSServer) getAddr() string {
	return s.addr
}

func (s *testDNSServer) getRequestCount() int {
	return int(atomic.LoadInt32(&s.requestCount))
}

func (s *testDNSServer) stop() {
	s.server.PacketConn.Close()
	s.server.Shutdown()
}
