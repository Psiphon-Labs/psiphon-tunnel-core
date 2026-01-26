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

// Package resolver implements a DNS stub resolver, or DNS client, which
// resolves domain names.
//
// The resolver is Psiphon-specific and oriented towards blocking resistance.
// See ResolveIP for more details.
package resolver

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/transforms"
	lrucache "github.com/cognusion/go-cache-lru"
	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

const (
	resolverCacheDefaultTTL          = 1 * time.Minute
	resolverCacheReapFrequency       = 1 * time.Minute
	resolverCacheMaxEntries          = 10000
	resolverServersUpdateTTL         = 5 * time.Second
	resolverDefaultAttemptsPerServer = 2
	resolverDefaultRequestTimeout    = 5 * time.Second
	resolverDefaultAwaitTimeout      = 10 * time.Millisecond
	resolverDefaultAnswerTTL         = 1 * time.Minute
	resolverDNSPort                  = "53"
	udpPacketBufferSize              = 1232
)

// NetworkConfig specifies network-level configuration for a Resolver.
type NetworkConfig struct {

	// GetDNSServers returns a list of system DNS server addresses (IP:port, or
	// IP only with port 53 assumed), as determined via OS APIs, in priority
	// order. GetDNSServers may be nil.
	GetDNSServers func() []string

	// BindToDevice should ensure the input file descriptor, a UDP socket, is
	// excluded from VPN routing. BindToDevice may be nil.
	BindToDevice func(fd int) (string, error)

	// AllowDefaultResolverWithBindToDevice indicates that it's safe to use
	// the default resolver when BindToDevice is configured, as the host OS
	// will automatically exclude DNS requests from the VPN.
	AllowDefaultResolverWithBindToDevice bool

	// IPv6Synthesize should apply NAT64 synthesis to the input IPv4 address,
	// returning a synthesized IPv6 address that will route to the same
	// endpoint. IPv6Synthesize may be nil.
	IPv6Synthesize func(IPv4 string) string

	// HasIPv6Route should return true when the host has an IPv6 route.
	// Resolver has an internal implementation, hasRoutableIPv6Interface, to
	// determine this, but it can fail on some platforms ("route ip+net:
	// netlinkrib: permission denied" on Android, for example; see Go issue
	// 40569). When HasIPv6Route is nil, the internal implementation is used.
	HasIPv6Route func() bool

	// LogWarning is an optional callback which is used to log warnings and
	// transient errors which would otherwise not be recorded or returned.
	LogWarning func(error)

	// LogHostnames indicates whether to log hostname in errors or not.
	LogHostnames bool

	// CacheExtensionInitialTTL specifies a minimum TTL to use when caching
	// domain resolution results. This minimum will override any TTL in the
	// DNS response. CacheExtensionInitialTTL is off when 0.
	CacheExtensionInitialTTL time.Duration

	// CacheExtensionVerifiedTTL specifies the minimum TTL to set for a cached
	// domain resolution result after the result has been verified.
	// CacheExtensionVerifiedTTL is off when 0.
	//
	// DNS cache extension is a workaround to partially mitigate issues with
	// obtaining underlying system DNS server IPs on platforms such as iOS
	// once a VPN is running and after network changes, such as changing from
	// Wi-Fi to mobile. While ResolveParameters.AlternateDNSServer can be
	// used to specify a known public DNS server, it may be the case that
	// public DNS servers are blocked or always falling back to a public DNS
	// server creates unusual traffic. And while it may be possible to use
	// the default system resolver, it lacks certain circumvention
	// capabilities.
	//
	// Extending the TTL for cached responses allows Psiphon to redial domains
	// using recently successful IPs.
	//
	// CacheExtensionInitialTTL allows for a greater initial minimum TTL, so
	// that the response entry remains in the cache long enough for a dial to
	// fully complete and verify the endpoint. Psiphon will call
	// Resolver.VerifyExtendCacheTTL once a dial has authenticated, for
	// example, the destination Psiphon server. VerifyCacheExtension will
	// further extend the corresponding TTL to CacheExtensionVerifiedTTL, a
	// longer TTL. CacheExtensionInitialTTL is intended to be on the order of
	// minutes and CacheExtensionVerifiedTTL may be on the order of hours.
	//
	// When CacheExtensionVerifiedTTL is on, the DNS cache is not flushed on
	// network changes, to allow for the previously cached entries to remain
	// available in the problematic scenario. Like adjusting TTLs, this is an
	// explicit trade-off which doesn't adhere to standard best practise, but
	// is expected to be more blocking resistent; this approach also assumes
	// that endpoints such as CDN IPs are typically available on any network.
	CacheExtensionVerifiedTTL time.Duration
}

func (c *NetworkConfig) allowDefaultResolver() bool {
	// When BindToDevice is configured, the standard library resolver is not
	// used, as the system resolver may not route outside of the VPN.
	return c.BindToDevice == nil || c.AllowDefaultResolverWithBindToDevice
}

func (c *NetworkConfig) logWarning(err error) {
	if c.LogWarning != nil {
		c.LogWarning(err)
	}
}

// ResolveParameters specifies the configuration and behavior of a single
// ResolveIP call, a single domain name resolution.
//
// New ResolveParameters may be generated by calling MakeResolveParameters,
// which takes tactics parameters as an input.
//
// ResolveParameters may be persisted for replay.
type ResolveParameters struct {

	// AttemptsPerServer specifies how many requests to send to each DNS
	// server before trying the next server. IPv4 and IPv6 requests are sent
	// concurrently and count as one attempt.
	AttemptsPerServer int

	// AttemptsPerPreferredServer is AttemptsPerServer for a preferred
	// alternate DNS server.
	AttemptsPerPreferredServer int

	// RequestTimeout specifies how long to wait for a valid response before
	// moving on to the next attempt.
	RequestTimeout time.Duration

	// AwaitTimeout specifies how long to await an additional response after
	// the first response is received. This additional wait time applies only
	// when there is either no IPv4 or IPv6 response.
	AwaitTimeout time.Duration

	// PreresolvedIPAddress specifies an IP address result to be used in place
	// of making a request.
	PreresolvedIPAddress string

	// PreresolvedDomain is the domain for which PreresolvedIPAddress is to be
	// used.
	PreresolvedDomain string

	// AlternateDNSServer specifies an alterate DNS server (IP:port, or IP
	// only with port 53 assumed) to be used when either no system DNS
	// servers are available or when PreferAlternateDNSServer is set.
	AlternateDNSServer string

	// PreferAlternateDNSServer indicates whether to prioritize using the
	// AlternateDNSServer. When set, the AlternateDNSServer is attempted
	// before any system DNS servers.
	PreferAlternateDNSServer bool

	// ProtocolTransformName specifies the name associated with
	// ProtocolTransformSpec and is used for metrics.
	ProtocolTransformName string

	// ProtocolTransformSpec specifies a transform to apply to the DNS request packet.
	// See: "github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/transforms".
	//
	// As transforms operate on strings and DNS requests are binary,
	// transforms should be expressed using hex characters.
	//
	// DNS transforms include strategies discovered by the Geneva team,
	// https://geneva.cs.umd.edu.
	ProtocolTransformSpec transforms.Spec

	// ProtocolTransformSeed specifies the seed to use for generating random
	// data in the ProtocolTransformSpec transform. To replay a transform,
	// specify the same seed.
	ProtocolTransformSeed *prng.Seed

	// RandomQNameCasingSeed specifies the seed for randomizing the casing of
	// the QName (hostname) in the DNS request. If not set, the QName casing
	// will remain unchanged. To reproduce the same random casing, use the same
	// seed.
	RandomQNameCasingSeed *prng.Seed

	// ResponseQNameMustMatch specifies whether the response's question section
	// must contain exactly one entry, and that entry's QName (hostname) must
	// exactly match the QName sent in the DNS request.
	//
	// RFC 1035 does not specify that the question section in the response must
	// exactly match the question section in the request, but this behavior is
	// expected [1].
	//
	// [1]: https://datatracker.ietf.org/doc/html/draft-vixie-dnsext-dns0x20-00#section-2.2.
	ResponseQNameMustMatch bool

	// IncludeEDNS0 indicates whether to include the EDNS(0) UDP maximum
	// response size extension in DNS requests. The resolver can handle
	// responses larger than 512 bytes (RFC 1035 maximum) regardless of
	// whether the extension is included; the extension may be included as
	// part of appearing similar to other DNS traffic.
	IncludeEDNS0 bool

	firstAttemptWithAnswer int32
	qnameMismatches        int32
}

// GetFirstAttemptWithAnswer returns the index of the first request attempt
// that received a valid response, for the most recent ResolveIP call using
// this ResolveParameters. This information is used for logging metrics. The
// first attempt has index 1. GetFirstAttemptWithAnswer return 0 when no
// request attempt has reported a valid response.
//
// The caller is responsible for synchronizing use of a ResolveParameters
// instance (e.g, use a distinct ResolveParameters per ResolveIP to ensure
// GetFirstAttemptWithAnswer refers to a specific ResolveIP).
func (r *ResolveParameters) GetFirstAttemptWithAnswer() int {
	return int(atomic.LoadInt32(&r.firstAttemptWithAnswer))
}

func (r *ResolveParameters) setFirstAttemptWithAnswer(attempt int) {
	atomic.StoreInt32(&r.firstAttemptWithAnswer, int32(attempt))
}

// GetQNameMismatches returns, for the most recent ResolveIP call using this
// ResolveParameters, the number of DNS requests where the response's question
// section either:
//   - Did not contain exactly one entry; or
//   - Contained one entry that had a QName (hostname) that did not match the
//     QName sent in the DNS request.
//
// This information is used for logging metrics.
//
// The caller is responsible for synchronizing use of a ResolveParameters
// instance (e.g, use a distinct ResolveParameters per ResolveIP to ensure
// GetQNameMismatches refers to a specific ResolveIP).
func (r *ResolveParameters) GetQNameMismatches() int {
	return int(atomic.LoadInt32(&r.qnameMismatches))
}

func (r *ResolveParameters) setQNameMismatches(mismatches int) {
	atomic.StoreInt32(&r.qnameMismatches, int32(mismatches))
}

// Implementation note: Go's standard net.Resolver supports specifying a
// custom Dial function. This could be used to implement at least a large
// subset of the Resolver functionality on top of Go's standard library
// resolver. However, net.Resolver is limited to using the CGO resolver on
// Android, https://github.com/golang/go/issues/8877, in which case the
// custom Dial function is not used. Furthermore, the the pure Go resolver in
// net/dnsclient_unix.go appears to not be used on Windows at this time.
//
// Go also provides golang.org/x/net/dns/dnsmessage, a DNS message marshaller,
// which could potentially be used in place of github.com/miekg/dns.

// Resolver is a DNS stub resolver, or DNS client, which resolves domain
// names. A Resolver instance maintains a cache, a network state snapshot,
// and metrics. All ResolveIP calls will share the same cache and state.
// Multiple concurrent ResolveIP calls are supported.
type Resolver struct {
	networkConfig *NetworkConfig

	mutex             sync.Mutex
	networkID         string
	hasIPv6Route      bool
	systemServers     []string
	lastServersUpdate time.Time
	cache             *lrucache.Cache
	metrics           resolverMetrics
}

type resolverMetrics struct {
	resolves                int
	cacheHits               int
	verifiedCacheExtensions int
	requestsIPv4            int
	requestsIPv6            int
	responsesIPv4           int
	responsesIPv6           int
	defaultResolves         int
	defaultSuccesses        int
	peakInFlight            int
	minRTT                  time.Duration
	maxRTT                  time.Duration
}

func newResolverMetrics() resolverMetrics {
	return resolverMetrics{minRTT: -1}
}

// NewResolver creates a new Resolver instance.
func NewResolver(networkConfig *NetworkConfig, networkID string) *Resolver {

	r := &Resolver{
		networkConfig: networkConfig,
		metrics:       newResolverMetrics(),
	}

	// updateNetworkState will initialize the cache and network state,
	// including system DNS servers.
	r.updateNetworkState(networkID)

	return r
}

// Stop clears the Resolver cache and resets metrics. Stop must be called only
// after ceasing all in-flight ResolveIP goroutines, or else the cache or
// metrics may repopulate. A Resolver may be resumed after calling Stop, but
// Update must be called first.
func (r *Resolver) Stop() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// r.networkConfig is not set to nil to avoid possible nil pointer
	// dereferences by concurrent ResolveIP calls.

	r.networkID = ""
	r.hasIPv6Route = false
	r.systemServers = nil
	r.cache.Flush()
	r.metrics = newResolverMetrics()
}

// MakeResolveParameters generates ResolveParameters using the input tactics
// parameters and optional frontingProviderID context.
func (r *Resolver) MakeResolveParameters(
	p parameters.ParametersAccessor,
	frontingProviderID string,
	frontingDialDomain string) (*ResolveParameters, error) {

	params := &ResolveParameters{
		AttemptsPerServer:          p.Int(parameters.DNSResolverAttemptsPerServer),
		AttemptsPerPreferredServer: p.Int(parameters.DNSResolverAttemptsPerPreferredServer),
		RequestTimeout:             p.Duration(parameters.DNSResolverRequestTimeout),
		AwaitTimeout:               p.Duration(parameters.DNSResolverAwaitTimeout),
	}

	// When a frontingProviderID is specified, generate a pre-resolved IP
	// address, based on tactics configuration.
	if frontingProviderID != "" {
		if frontingDialDomain == "" {
			return nil, errors.TraceNew("missing fronting dial domain")
		}
		if p.WeightedCoinFlip(parameters.DNSResolverPreresolvedIPAddressProbability) {
			CIDRs := p.LabeledCIDRs(parameters.DNSResolverPreresolvedIPAddressCIDRs, frontingProviderID)
			if len(CIDRs) > 0 {
				CIDR := CIDRs[prng.Intn(len(CIDRs))]
				IP, err := generateIPAddressFromCIDR(CIDR)
				if err != nil {
					return nil, errors.Trace(err)
				}
				params.PreresolvedIPAddress = IP.String()
				params.PreresolvedDomain = frontingDialDomain
			}
		}
	}

	// When preferring an alternate DNS server, select the alternate from
	// DNSResolverPreferredAlternateServers. This list is for circumvention
	// operations, such as using a public DNS server with a protocol
	// transform. Otherwise, select from DNSResolverAlternateServers, which
	// is a fallback list of DNS servers to be used when the system DNS
	// servers cannot be obtained.

	preferredServers := p.Strings(parameters.DNSResolverPreferredAlternateServers)
	preferAlternateDNSServer := len(preferredServers) > 0 && p.WeightedCoinFlip(
		parameters.DNSResolverPreferAlternateServerProbability)

	alternateServers := preferredServers
	if !preferAlternateDNSServer {
		alternateServers = p.Strings(parameters.DNSResolverAlternateServers)
	}

	// Select an alternate DNS server, typically a public DNS server. Ensure
	// tactics is configured with an empty DNSResolverAlternateServers list
	// in cases where attempts to public DNS server are unwanted.
	if len(alternateServers) > 0 {

		alternateServer := alternateServers[prng.Intn(len(alternateServers))]

		// Check that the alternateServer has a well-formed IP address; and add
		// a default port if none it present.
		host, _, err := net.SplitHostPort(alternateServer)
		if err != nil {
			// Assume the SplitHostPort error is due to missing port.
			host = alternateServer
			alternateServer = net.JoinHostPort(alternateServer, resolverDNSPort)
		}
		if net.ParseIP(host) == nil {
			// Log warning and proceed without this DNS server.
			r.networkConfig.logWarning(
				errors.TraceNew("invalid alternate DNS server IP address"))

		} else {

			params.AlternateDNSServer = alternateServer
			params.PreferAlternateDNSServer = preferAlternateDNSServer
		}

	}

	// Select a DNS transform. DNS request transforms are "scoped" by
	// alternate DNS server (IP address without port); that is, when an
	// alternate DNS server is certain to be attempted first, a transform
	// associated with and known to work with that DNS server will be
	// selected. Otherwise, a transform from the default scope
	// (transforms.SCOPE_ANY == "") is selected.
	//
	// In any case, ResolveIP will only apply a transform on the first request
	// attempt.
	if p.WeightedCoinFlip(parameters.DNSResolverProtocolTransformProbability) {

		specs := p.ProtocolTransformSpecs(
			parameters.DNSResolverProtocolTransformSpecs)
		scopedSpecNames := p.ProtocolTransformScopedSpecNames(
			parameters.DNSResolverProtocolTransformScopedSpecNames)

		// The alternate DNS server will be the first attempt if
		// PreferAlternateDNSServer or the list of system DNS servers is empty.
		//
		// Limitation: the system DNS server list may change, due to a later
		// Resolver.update call when ResolveIP is called with these
		// ResolveParameters.
		_, systemServers := r.getNetworkState()
		scope := transforms.SCOPE_ANY
		if params.AlternateDNSServer != "" &&
			(params.PreferAlternateDNSServer || len(systemServers) == 0) {

			// Remove the port number, as the scope key is an IP address only.
			//
			// TODO: when we only just added the default port above, which is
			// the common case, we could avoid this extra split.
			host, _, err := net.SplitHostPort(params.AlternateDNSServer)
			if err != nil {
				return nil, errors.Trace(err)
			}
			scope = host
		}

		name, spec := specs.Select(scope, scopedSpecNames)

		if spec != nil {
			params.ProtocolTransformName = name
			params.ProtocolTransformSpec = spec
			var err error
			params.ProtocolTransformSeed, err = prng.NewSeed()
			if err != nil {
				return nil, errors.Trace(err)
			}
		}
	}

	if p.WeightedCoinFlip(parameters.DNSResolverQNameRandomizeCasingProbability) {
		var err error
		params.RandomQNameCasingSeed, err = prng.NewSeed()
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	params.ResponseQNameMustMatch = p.WeightedCoinFlip(parameters.DNSResolverQNameMustMatchProbability)

	if p.WeightedCoinFlip(parameters.DNSResolverIncludeEDNS0Probability) {
		params.IncludeEDNS0 = true
	}

	return params, nil
}

// ResolveAddress splits the input host:port address, calls ResolveIP to
// resolve the IP address of the host, selects an IP if there are multiple,
// and returns a rejoined IP:port.
//
// IP address selection is random. When network input is set
// to "ip4"/"tcp4"/"udp4" or "ip6"/"tcp6"/"udp6", selection is limited to
// IPv4 or IPv6, respectively.
func (r *Resolver) ResolveAddress(
	ctx context.Context,
	networkID string,
	params *ResolveParameters,
	network, address string) (string, error) {

	hostname, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", errors.Trace(err)
	}

	IPs, err := r.ResolveIP(ctx, networkID, params, hostname)
	if err != nil {
		return "", errors.Trace(err)
	}

	// Don't shuffle or otherwise mutate the slice returned by ResolveIP.
	permutedIndexes := prng.Perm(len(IPs))

	index := 0

	switch network {
	case "ip4", "tcp4", "udp4":
		index = -1
		for _, i := range permutedIndexes {
			if IPs[i].To4() != nil {
				index = i
				break
			}
		}
	case "ip6", "tcp6", "udp6":
		index = -1
		for _, i := range permutedIndexes {
			if IPs[i].To4() == nil {
				index = i
				break
			}
		}
	}

	if index == -1 {
		return "", errors.Tracef("no IP for network '%s'", network)
	}

	return net.JoinHostPort(IPs[index].String(), port), nil
}

// ResolveIP resolves a domain name.
//
// The input params may be nil, in which case default timeouts are used.
//
// ResolveIP performs concurrent A and AAAA lookups, returns any valid
// response IPs, and caches results. An error is returned when there are
// no valid response IPs.
//
// ResolveIP is not a general purpose resolver and is Psiphon-specific. For
// example, resolved domains are expected to exist; ResolveIP does not
// fallback to TCP; does not consult any "hosts" file; does not perform RFC
// 3484 sorting logic (see Go issue 18518); only implements a subset of
// Go/glibc/resolv.conf(5) resolver parameters (attempts and timeouts, but
// not rotate, single-request etc.) ResolveIP does not implement singleflight
// logic, as the Go resolver does, and allows multiple concurrent request for
// the same domain -- Psiphon won't often resolve the exact same domain
// multiple times concurrently, and, when it does, there's a circumvention
// benefit to attempting different DNS servers and protocol transforms.
//
// ResolveIP does not currently support DoT, DoH, or TCP; those protocols are
// often blocked or less common. Instead, ResolveIP makes a best effort to
// evade plaintext UDP DNS interference by ignoring invalid responses and by
// optionally applying protocol transforms that may evade blocking.
//
// Due to internal caching, the caller must not mutate returned net.IP slice
// or entries.
func (r *Resolver) ResolveIP(
	ctx context.Context,
	networkID string,
	params *ResolveParameters,
	hostname string) ([]net.IP, error) {

	// ResolveIP does _not_ lock r.mutex for the lifetime of the function, to
	// ensure many ResolveIP calls can run concurrently.

	// If the hostname is already an IP address, just return that. For
	// metrics, this does not count as a resolve, as the caller may invoke
	// ResolveIP for all dials.
	IP := net.ParseIP(hostname)
	if IP != nil {
		return []net.IP{IP}, nil
	}

	// Count all resolves of an actual domain, including cached and
	// pre-resolved cases.
	r.updateMetricResolves()

	// Call updateNetworkState immediately before resolving, as a best effort
	// to ensure that system DNS servers and IPv6 routing network state
	// reflects the current network. updateNetworkState locks the Resolver
	// mutex for its duration, and so concurrent ResolveIP calls may block at
	// this point. However, all updateNetworkState operations are local to
	// the host or device; and, if the networkID is unchanged since the last
	// call, updateNetworkState may not perform any operations; and after the
	// updateNetworkState call, ResolveIP proceeds without holding the mutex
	// lock. As a result, this step should not prevent ResolveIP concurrency.
	r.updateNetworkState(networkID)

	if params == nil {
		// Supply default ResolveParameters
		params = &ResolveParameters{
			AttemptsPerServer:          resolverDefaultAttemptsPerServer,
			AttemptsPerPreferredServer: resolverDefaultAttemptsPerServer,
			RequestTimeout:             resolverDefaultRequestTimeout,
			AwaitTimeout:               resolverDefaultAwaitTimeout,
		}
	}

	// When PreresolvedIPAddress is set, tactics parameters determined the IP address
	// in this case.
	if params.PreresolvedIPAddress != "" && params.PreresolvedDomain == hostname {
		IP := net.ParseIP(params.PreresolvedIPAddress)
		if IP == nil {
			// Unexpected case, as MakeResolveParameters selects the IP address.
			return nil, errors.TraceNew("invalid IP address")
		}
		return []net.IP{IP}, nil
	}

	// Use a snapshot of the current network state, including IPv6 routing and
	// system DNS servers.
	//
	// Limitation: these values are used even if the network changes in the
	// middle of a ResolveIP call; ResolveIP is not interrupted if the
	// network changes.
	hasIPv6Route, systemServers := r.getNetworkState()

	// Use the standard library resolver when there's no GetDNSServers, or the
	// system server list is otherwise empty, and no alternate DNS server is
	// configured.
	//
	// Note that in the case where there are no system DNS servers and there
	// is an AlternateDNSServer, if the AlternateDNSServer attempt fails,
	// control does not flow back to defaultResolverLookupIP. On platforms
	// without GetDNSServers, the caller must arrange for distinct attempts
	// that try a AlternateDNSServer, or just use the standard library
	// resolver.
	//
	// ResolveIP should always be called, even when defaultResolverLookupIP is
	// expected to be used, to ensure correct metrics counts and ensure a
	// consistent error message log stack for all DNS-related failures.
	//
	if len(systemServers) == 0 &&
		params.AlternateDNSServer == "" &&
		r.networkConfig.allowDefaultResolver() {

		IPs, err := defaultResolverLookupIP(ctx, hostname, r.networkConfig.LogHostnames)
		r.updateMetricDefaultResolver(err == nil)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return IPs, err
	}

	// Consult the cache before making queries. This comes after the standard
	// library case, to allow the standard library to provide its own caching
	// logic.
	IPs := r.getCache(hostname)
	if IPs != nil {
		// TODO: it would be safer to make and return a copy of the cached
		// slice, instead of depending on all callers to not mutate the slice.
		return IPs, nil
	}

	// Set the list of DNS servers to attempt. AlternateDNSServer is used
	// first when PreferAlternateDNSServer is set; otherwise
	// AlternateDNSServer is used only when there is no system DNS server.
	var servers []string
	if params.AlternateDNSServer != "" &&
		(len(systemServers) == 0 || params.PreferAlternateDNSServer) {
		servers = []string{params.AlternateDNSServer}
	}
	servers = append(servers, systemServers...)
	if len(servers) == 0 {
		return nil, errors.TraceNew("no DNS servers")
	}

	// Set the request timeout and set up a reusable timer for handling
	// request and await timeouts.
	//
	// We expect to always have a request timeout. Handle the unexpected no
	// timeout, 0, case by setting the longest timeout possible, ~290 years;
	// always having a non-zero timeout makes the following code marginally
	// simpler.
	requestTimeout := params.RequestTimeout
	if requestTimeout == 0 {
		requestTimeout = 1<<63 - 1
	}
	var timer *time.Timer
	timerDrained := true
	resetTimer := func(timeout time.Duration) {
		if timer == nil {
			timer = time.NewTimer(timeout)
		} else {
			if !timerDrained && !timer.Stop() {
				<-timer.C
			}
			timer.Reset(timeout)
		}
		timerDrained = false
	}

	// Orchestrate the DNS requests

	resolveCtx, cancelFunc := context.WithCancelCause(ctx)
	defer cancelFunc(nil)
	waitGroup := new(sync.WaitGroup)
	conns := common.NewConns[net.Conn]()
	type answer struct {
		attempt      int
		questionType resolverQuestionType
		IPs          []net.IP
		TTLs         []time.Duration
	}
	var maxAttempts int
	if params.PreferAlternateDNSServer {
		maxAttempts = params.AttemptsPerPreferredServer
		maxAttempts += (len(servers) - 1) * params.AttemptsPerServer
	} else {
		maxAttempts = len(servers) * params.AttemptsPerServer
	}
	answerChan := make(chan *answer, maxAttempts*2)
	inFlight := 0
	awaitA := true
	awaitAAAA := hasIPv6Route
	var result *answer
	var lastErr atomic.Value

	trackResult := func(a *answer) {

		// A result is sent from every attempt goroutine that is launched,
		// even in the case of an error, in which case the result is nil.
		// Update the number of in-flight attempts as results are received.
		// Mark no longer awaiting A or AAAA as long as there is a valid
		// response, even if there are no IPs in the IPv6 case.
		if inFlight > 0 {
			inFlight -= 1
		}
		if a != nil {
			switch a.questionType {
			case resolverQuestionTypeA:
				awaitA = false
			case resolverQuestionTypeAAAA:
				awaitAAAA = false
			}
		}
	}

	stop := false
	for i := 0; !stop && i < maxAttempts; i++ {

		var index int
		if params.PreferAlternateDNSServer {
			if i < params.AttemptsPerPreferredServer {
				index = 0
			} else {
				index = 1 + ((i - params.AttemptsPerPreferredServer) / params.AttemptsPerServer)
			}
		} else {
			index = i / params.AttemptsPerServer
		}

		server := servers[index]

		// Only the first attempt pair tries techniques that may not be
		// compatible with all DNS servers.
		useProtocolTransform := (i == 0 && params.ProtocolTransformSpec != nil)
		useRandomQNameCasing := (i == 0 && params.RandomQNameCasingSeed != nil)
		responseQNameMustMatch := (i == 0 && params.ResponseQNameMustMatch)

		// Send A and AAAA requests concurrently.
		questionTypes := []resolverQuestionType{resolverQuestionTypeA, resolverQuestionTypeAAAA}
		if !hasIPv6Route {
			questionTypes = questionTypes[0:1]
		}

		for _, questionType := range questionTypes {

			waitGroup.Add(1)

			// For metrics, track peak concurrent in-flight requests for
			// a _single_ ResolveIP. inFlight for this ResolveIP is also used
			// to determine whether to await additional responses once the
			// first, valid response is received. For that logic to be
			// correct, we must increment inFlight in this outer goroutine to
			// ensure the await logic sees either inFlight > 0 or an answer
			// in the channel.
			inFlight += 1
			r.updateMetricPeakInFlight(inFlight)

			go func(attempt int, questionType resolverQuestionType, useProtocolTransform, useRandomQNameCasing, responseQNameMustMatch bool) {
				defer waitGroup.Done()

				// Always send a result back to the main loop, even if this
				// attempt fails, so the main loop proceeds to the next
				// iteration immediately. Nil is sent in failure cases. When
				// the answer is not nil, it's already been sent.
				var a *answer
				defer func() {
					if a == nil {
						// The channel should have sufficient buffering for
						// the send to never block; the default case is used
						// to avoid a hang in the case of a bug.
						select {
						case answerChan <- a:
						default:
						}
					}
				}()

				// The request count metric counts the _intention_ to send
				// requests, as there's a possibility that newResolverConn or
				// performDNSQuery fail locally before sending a request packet.
				switch questionType {
				case resolverQuestionTypeA:
					r.updateMetricRequestsIPv4()
				case resolverQuestionTypeAAAA:
					r.updateMetricRequestsIPv6()
				}

				// While it's possible, and potentially more optimal, to use
				// the same UDP socket for both the A and AAAA request, we
				// use a distinct socket per request, as common DNS clients do.
				conn, err := r.newResolverConn(r.networkConfig.logWarning, server)
				if err != nil {
					lastErr.Store(errors.Trace(err))
					return
				}
				defer conn.Close()

				// There's no context.Context support in the underlying API
				// used by performDNSQuery, so instead collect all the
				// request conns so that they can be closed, and any blocking
				// network I/O interrupted, below, if resolveCtx is done.
				if !conns.Add(conn) {
					// Add fails when conns is already closed. Do not
					// overwrite lastErr in this case.
					return
				}

				// performDNSQuery will send the request and read a response.
				// performDNSQuery will continue reading responses until it
				// receives a valid response, which can mitigate a subset of
				// DNS injection attacks (to the limited extent possible for
				// plaintext DNS).
				//
				// For IPv4, NXDOMAIN or a response with no IPs is not
				// expected for domains resolved by Psiphon, so
				// performDNSQuery treats such a response as invalid. For
				// IPv6, a response with no IPs, may be valid(even though the
				// response could be forged); the resolver will continue its
				// attempts loop if it has no other IPs.
				//
				// Each performDNSQuery has no timeout and runs
				// until it has read a valid response or the requestCtx is
				// done. This allows for slow arriving, valid responses to
				// eventually succeed, even if the read time exceeds
				// requestTimeout, as long as the read time is less than the
				// requestCtx timeout.
				//
				// With this approach, the overall ResolveIP call may have
				// more than 2 performDNSQuery requests in-flight at a time,
				// as requestTimeout is used to schedule sending the next
				// attempt but not cancel the current attempt. For
				// connectionless UDP, the resulting network traffic should
				// be similar to common DNS clients which do cancel request
				// before beginning the next attempt.
				IPs, TTLs, RTT, err := performDNSQuery(
					resolveCtx,
					r.networkConfig.logWarning,
					params,
					useProtocolTransform,
					useRandomQNameCasing,
					conn,
					questionType,
					hostname,
					responseQNameMustMatch)

				// Update the min/max RTT metric when reported (>=0) even if
				// the result is an error; i.e., the even if there was an
				// invalid response.
				//
				// Limitation: since individual requests aren't cancelled
				// after requestTimeout, RTT metrics won't reflect
				// no-response cases, although request and response count
				// disparities will still show up in the metrics.
				if RTT >= 0 {
					r.updateMetricRTT(RTT)
				}

				if err != nil {
					lastErr.Store(errors.Trace(err))
					return
				}

				// Update response stats.
				switch questionType {
				case resolverQuestionTypeA:
					r.updateMetricResponsesIPv4()
				case resolverQuestionTypeAAAA:
					r.updateMetricResponsesIPv6()
				}

				// Send the answer back to the main loop.
				if len(IPs) > 0 || questionType == resolverQuestionTypeAAAA {
					a = &answer{
						attempt:      attempt,
						questionType: questionType,
						IPs:          IPs,
						TTLs:         TTLs}

					// The channel should have sufficient buffering for
					// the send to never block; the default case is used
					// to avoid a hang in the case of a bug.
					select {
					case answerChan <- a:
					default:
					}
				}

			}(i+1, questionType, useProtocolTransform, useRandomQNameCasing, responseQNameMustMatch)
		}

		resetTimer(requestTimeout)

		select {
		case result = <-answerChan:
			trackResult(result)
			if result != nil {
				// When the first answer, a response with valid IPs, arrives, exit
				// the attempts loop. The following await branch may collect
				// additional answers.
				params.setFirstAttemptWithAnswer(result.attempt)
				stop = true
			}
		case <-timer.C:
			// When requestTimeout arrives, loop around and launch the next
			// attempt; leave the existing requests running in case they
			// eventually respond.
			timerDrained = true
		case <-resolveCtx.Done():
			// When resolveCtx is done, exit the attempts loop.
			//
			// Append the existing lastErr, which may convey useful
			// information to be reported in a failed_tunnel error message.
			lastErr.Store(errors.Tracef(
				"%v (lastErr: %v)", context.Cause(resolveCtx), lastErr.Load()))
			stop = true
		}
	}

	// Receive any additional answers, now present in the channel, which
	// arrived concurrent with the first answer. This receive avoids a race
	// condition where inFlight may now be 0, with additional answers
	// enqueued, in which case the following await branch is not taken.
	//
	// It's possible for the attempts loop to exit with no received answer due
	// to timeouts or cancellation while, concurrently, an answer is sent to
	// the channel. In this case, when result == nil, we ignore the answers
	// and leave this as a failed resolve.
	if result != nil {
		for loop := true; loop; {
			select {
			case nextAnswer := <-answerChan:
				trackResult(nextAnswer)
				if nextAnswer != nil {
					result.IPs = append(result.IPs, nextAnswer.IPs...)
					result.TTLs = append(result.TTLs, nextAnswer.TTLs...)
				}
			default:
				loop = false
			}
		}
	}

	// When we have an answer, await -- for a short time,
	// params.AwaitTimeout -- extra answers from any remaining in-flight
	// requests. Only await if the request isn't cancelled and we don't
	// already have at least one IPv4 and one IPv6 response; only await AAAA
	// if it was sent; note that a valid AAAA response may include no IPs
	// lastErr is not set in timeout/cancelled cases here, since we already
	// have an answer.
	if result != nil &&
		resolveCtx.Err() == nil &&
		inFlight > 0 &&
		(awaitA || awaitAAAA) &&
		params.AwaitTimeout > 0 {

		resetTimer(params.AwaitTimeout)

		for {

			stop := false
			select {
			case nextAnswer := <-answerChan:
				trackResult(nextAnswer)
				if nextAnswer != nil {
					result.IPs = append(result.IPs, nextAnswer.IPs...)
					result.TTLs = append(result.TTLs, nextAnswer.TTLs...)
				}
			case <-timer.C:
				timerDrained = true
				stop = true
			case <-resolveCtx.Done():
				stop = true
			}

			if stop || inFlight == 0 || (!awaitA && !awaitAAAA) {

				break
			}
		}
	}

	if timer != nil {
		timer.Stop()
	}

	// Interrupt all workers.
	cancelFunc(errors.TraceNew("resolve canceled"))
	conns.CloseAll()
	waitGroup.Wait()

	// When there's no answer, or when there's only an empty IPv6 answer,
	// return the last error.
	if result == nil ||
		(result.questionType == resolverQuestionTypeAAAA && len(result.IPs) == 0) {

		err := lastErr.Load()
		if err == nil {
			err = context.Cause(resolveCtx)
		}
		if err == nil {
			err = errors.TraceNew("unexpected missing error")
		}
		if r.networkConfig.LogHostnames {
			err = fmt.Errorf("resolve %s : %w", hostname, err.(error))
		}
		return nil, errors.Trace(err.(error))
	}

	if len(result.IPs) == 0 {
		// Unexpected, since a len(IPs) > 0 check precedes sending to answerChan.
		return nil, errors.TraceNew("unexpected no IPs")
	}

	// Update the cache now, after all results are gathered.
	r.setCache(hostname, result.IPs, result.TTLs)

	return result.IPs, nil
}

// VerifyCacheExtension extends the TTL for any cached result for the
// specified hostname to at least NetworkConfig.CacheExtensionVerifiedTTL.
func (r *Resolver) VerifyCacheExtension(hostname string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.networkConfig.CacheExtensionVerifiedTTL == 0 {
		return
	}

	if net.ParseIP(hostname) != nil {
		return
	}

	entry, expires, ok := r.cache.GetWithExpiration(hostname)
	if !ok {
		return
	}

	// Change the TTL only if the entry expires and the existing TTL isn't
	// longer than the extension.
	neverExpires := time.Time{}
	if expires == neverExpires ||
		expires.After(time.Now().Add(r.networkConfig.CacheExtensionVerifiedTTL)) {
		return
	}

	r.cache.Set(hostname, entry, r.networkConfig.CacheExtensionVerifiedTTL)

	r.metrics.verifiedCacheExtensions += 1
}

// GetMetrics returns a summary of DNS metrics.
func (r *Resolver) GetMetrics() string {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// When r.metrics.minRTT < 0, min/maxRTT is unset.
	minRTT := "n/a"
	maxRTT := minRTT
	if r.metrics.minRTT >= 0 {
		minRTT = fmt.Sprintf("%d", r.metrics.minRTT/time.Millisecond)
		maxRTT = fmt.Sprintf("%d", r.metrics.maxRTT/time.Millisecond)
	}

	extend := ""
	if r.networkConfig.CacheExtensionVerifiedTTL > 0 {
		extend = fmt.Sprintf("| extend %d ", r.metrics.verifiedCacheExtensions)
	}

	defaultResolves := ""
	if r.networkConfig.allowDefaultResolver() {
		defaultResolves = fmt.Sprintf(
			" | def %d/%d", r.metrics.defaultResolves, r.metrics.defaultSuccesses)
	}

	// Note that the number of system resolvers is a point-in-time value,
	// while the others are cumulative.

	return fmt.Sprintf("resolves %d | hit %d %s| req v4/v6 %d/%d | resp %d/%d | peak %d | rtt %s - %s ms. | sys %d%s",
		r.metrics.resolves,
		r.metrics.cacheHits,
		extend,
		r.metrics.requestsIPv4,
		r.metrics.requestsIPv6,
		r.metrics.responsesIPv4,
		r.metrics.responsesIPv6,
		r.metrics.peakInFlight,
		minRTT,
		maxRTT,
		len(r.systemServers),
		defaultResolves)
}

// updateNetworkState updates the system DNS server list, IPv6 state, and the
// cache.
//
// Any errors that occur while querying network state are logged; in error
// conditions the functionality of the resolver may be reduced, but the
// resolver remains operational.
func (r *Resolver) updateNetworkState(networkID string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Only perform blocking/expensive update operations when necessary.
	updateAll := false
	updateIPv6Route := false
	updateServers := false
	flushCache := false

	// If r.cache is nil, this is the first update call in NewResolver. Create
	// the cache and perform all updates.
	if r.cache == nil {
		r.cache = lrucache.NewWithLRU(
			resolverCacheDefaultTTL,
			resolverCacheReapFrequency,
			resolverCacheMaxEntries)
		updateAll = true
	}

	// Perform all updates when the networkID has changed, which indicates a
	// different network.
	if r.networkID != networkID {
		updateAll = true
	}

	if updateAll {
		updateIPv6Route = true
		updateServers = true
		flushCache = true
	}

	// Even when the networkID has not changed, update DNS servers
	// periodically. This is similar to how other DNS clients
	// poll /etc/resolv.conf, including the period of 5s.
	if time.Since(r.lastServersUpdate) > resolverServersUpdateTTL {
		updateServers = true
	}

	// Update hasIPv6Route, which indicates whether the current network has an
	// IPv6 route and so if DNS requests for AAAA records will be sent.
	// There's no use for AAAA records on IPv4-only networks; and other
	// common DNS clients omit AAAA requests on IPv4-only records, so these
	// requests would otherwise be unusual.
	//
	// There's no hasIPv4Route as we always need to resolve A records,
	// particularly for IPv4-only endpoints; for IPv6-only networks,
	// NetworkConfig.IPv6Synthesize should be used to accomodate IPv4 DNS
	// server addresses, and dials performed outside the Resolver will
	// similarly use NAT 64 (on iOS; on Android, 464XLAT will handle this
	// transparently).
	if updateIPv6Route {

		// TODO: the HasIPv6Route callback provides hasRoutableIPv6Interface
		// functionality on platforms where that internal implementation
		// fails. In particular, "route ip+net: netlinkrib: permission
		// denied" on Android; see Go issue 40569). This Android case can be
		// fixed, and the callback retired, by sharing the workaround now
		// implemented in inproxy.pionNetwork.Interfaces.

		if r.networkConfig.HasIPv6Route != nil {

			r.hasIPv6Route = r.networkConfig.HasIPv6Route()

		} else {

			hasIPv6Route, err := hasRoutableIPv6Interface()
			if err != nil {
				// Log warning and proceed without IPv6.
				r.networkConfig.logWarning(
					errors.Tracef("unable to determine IPv6 route: %v", err))
				hasIPv6Route = false
			}
			r.hasIPv6Route = hasIPv6Route
		}
	}

	// Update the list of system DNS servers. It's not an error condition here
	// if the list is empty: a subsequent ResolveIP may use
	// ResolveParameters which specifies an AlternateDNSServer.
	if updateServers && r.networkConfig.GetDNSServers != nil {

		systemServers := []string{}
		for _, systemServer := range r.networkConfig.GetDNSServers() {
			host, _, err := net.SplitHostPort(systemServer)
			if err != nil {
				// Assume the SplitHostPort error is due to systemServer being
				// an IP only, and append the default port, 53. If
				// systemServer _isn't_ an IP, the following ParseIP will fail.
				host = systemServer
				systemServer = net.JoinHostPort(systemServer, resolverDNSPort)
			}
			if net.ParseIP(host) == nil {
				// Log warning and proceed without this DNS server.
				r.networkConfig.logWarning(
					errors.TraceNew("invalid DNS server IP address"))
				continue
			}
			systemServers = append(systemServers, systemServer)
		}

		// Check if the list of servers has changed, including order. If
		// changed, flush the cache even if the networkID has not changed.
		// Cached results are only considered valid as long as the system DNS
		// configuration remains the same.
		equal := len(r.systemServers) == len(systemServers)
		if equal {
			for i := 0; i < len(r.systemServers); i++ {
				if r.systemServers[i] != systemServers[i] {
					equal = false
					break
				}
			}
		}
		flushCache = flushCache || !equal

		// Concurrency note: once the r.systemServers slice is set, the
		// contents of the backing array must not be modified due to
		// concurrent ResolveIP calls.
		r.systemServers = systemServers

		r.lastServersUpdate = time.Now()
	}

	// Skip cache flushes when the extended DNS caching mechanism is enabled.
	// TODO: retain only verified cache entries?
	if flushCache && r.networkConfig.CacheExtensionVerifiedTTL == 0 {
		r.cache.Flush()
	}

	// Set r.networkID only after all operations complete without errors; if
	// r.networkID were set earlier, a subsequent
	// ResolveIP/updateNetworkState call might proceed as if the network
	// state were updated for the specified network ID.
	r.networkID = networkID
}

func (r *Resolver) getNetworkState() (bool, []string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	return r.hasIPv6Route, r.systemServers
}

func (r *Resolver) setCache(hostname string, IPs []net.IP, TTLs []time.Duration) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// The shortest TTL is used. In some cases, a DNS server may omit the TTL
	// or set a 0 TTL, in which case the default is used.
	TTL := resolverDefaultAnswerTTL
	for _, answerTTL := range TTLs {
		if answerTTL > 0 && answerTTL < TTL {
			TTL = answerTTL
		}
	}

	// When NetworkConfig.CacheExtensionInitialTTL configured, ensure the TTL
	// is no shorter than CacheExtensionInitialTTL.
	if r.networkConfig.CacheExtensionInitialTTL != 0 &&
		TTL < r.networkConfig.CacheExtensionInitialTTL {

		TTL = r.networkConfig.CacheExtensionInitialTTL
	}

	// Limitation: with concurrent ResolveIPs for the same domain, the last
	// setCache call determines the cache value. The results are not merged.

	r.cache.Set(hostname, IPs, TTL)
}

func (r *Resolver) getCache(hostname string) []net.IP {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	entry, ok := r.cache.Get(hostname)
	if !ok {
		return nil
	}
	r.metrics.cacheHits += 1
	return entry.([]net.IP)
}

// newResolverConn creates a UDP socket that will send packets to serverAddr.
// serverAddr is an IP:port, which allows specifying the port for testing or
// in rare cases where the port isn't 53.
func (r *Resolver) newResolverConn(
	logWarning func(error),
	serverAddr string) (retConn net.Conn, retErr error) {

	defer func() {
		if retErr != nil {
			logWarning(retErr)
		}
	}()

	// When configured, attempt to synthesize an IPv6 address from
	// an IPv4 address for compatibility on DNS64/NAT64 networks.
	// If synthesize fails, try the original address.
	if r.networkConfig.IPv6Synthesize != nil {
		serverIPStr, port, err := net.SplitHostPort(serverAddr)
		if err != nil {
			return nil, errors.Trace(err)
		}
		serverIP := net.ParseIP(serverIPStr)
		if serverIP != nil && serverIP.To4() != nil {
			synthesized := r.networkConfig.IPv6Synthesize(serverIPStr)
			if synthesized != "" && net.ParseIP(synthesized) != nil {
				serverAddr = net.JoinHostPort(synthesized, port)
			}
		}
	}

	dialer := &net.Dialer{}
	if r.networkConfig.BindToDevice != nil {
		dialer.Control = func(_, _ string, c syscall.RawConn) error {
			var controlErr error
			err := c.Control(func(fd uintptr) {
				_, err := r.networkConfig.BindToDevice(int(fd))
				if err != nil {
					controlErr = errors.Tracef("BindToDevice failed: %v", err)
					return
				}
			})
			if controlErr != nil {
				return errors.Trace(controlErr)
			}
			return errors.Trace(err)
		}
	}

	// context.Background is ok in this case as the UDP dial is just a local
	// syscall to create the socket.
	conn, err := dialer.DialContext(context.Background(), "udp", serverAddr)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return conn, nil
}

func (r *Resolver) updateMetricResolves() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.metrics.resolves += 1
}

func (r *Resolver) updateMetricRequestsIPv4() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.metrics.requestsIPv4 += 1
}

func (r *Resolver) updateMetricRequestsIPv6() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.metrics.requestsIPv6 += 1
}

func (r *Resolver) updateMetricResponsesIPv4() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.metrics.responsesIPv4 += 1
}

func (r *Resolver) updateMetricResponsesIPv6() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.metrics.responsesIPv6 += 1
}

func (r *Resolver) updateMetricDefaultResolver(success bool) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.metrics.defaultResolves += 1
	if success {
		r.metrics.defaultSuccesses += 1
	}
}

func (r *Resolver) updateMetricPeakInFlight(inFlight int) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if inFlight > r.metrics.peakInFlight {
		r.metrics.peakInFlight = inFlight
	}
}

func (r *Resolver) updateMetricRTT(rtt time.Duration) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if rtt < 0 {
		// Ignore invalid input.
		return
	}

	// When r.metrics.minRTT < 0, min/maxRTT is unset.
	if r.metrics.minRTT < 0 || rtt < r.metrics.minRTT {
		r.metrics.minRTT = rtt
	}

	if rtt > r.metrics.maxRTT {
		r.metrics.maxRTT = rtt
	}
}

func hasRoutableIPv6Interface() (bool, error) {

	interfaces, err := net.Interfaces()
	if err != nil {
		return false, errors.Trace(err)
	}

	for _, in := range interfaces {

		if (in.Flags&net.FlagUp == 0) ||
			// Note: don't exclude interfaces with the net.FlagPointToPoint
			// flag, which is set for certain mobile networks
			(in.Flags&net.FlagLoopback != 0) {
			continue
		}

		addrs, err := in.Addrs()
		if err != nil {
			return false, errors.Trace(err)
		}

		for _, addr := range addrs {
			if IPNet, ok := addr.(*net.IPNet); ok &&
				IPNet.IP.To4() == nil &&
				!IPNet.IP.IsLinkLocalUnicast() {

				return true, nil
			}
		}
	}

	return false, nil
}

func generateIPAddressFromCIDR(CIDR string) (net.IP, error) {
	_, IPNet, err := net.ParseCIDR(CIDR)
	if err != nil {
		return nil, errors.Trace(err)
	}
	// A retry is required, since a CIDR may include broadcast IPs (a.b.c.0) or
	// other invalid values. The number of retries is limited to ensure we
	// don't hang in the case of a misconfiguration.
	for i := 0; i < 10; i++ {
		randBytes := prng.Bytes(len(IPNet.IP))
		IP := make(net.IP, len(IPNet.IP))
		// The 1 bits in the mask must apply to the IP in the CIDR and the 0
		// bits in the mask are available to randomize.
		for i := 0; i < len(IP); i++ {
			IP[i] = (IPNet.IP[i] & IPNet.Mask[i]) | (randBytes[i] & ^IPNet.Mask[i])
		}
		if IP.IsGlobalUnicast() && !common.IsBogon(IP) {
			return IP, nil
		}
	}
	return nil, errors.TraceNew("failed to generate random IP")
}

type resolverQuestionType int

const (
	resolverQuestionTypeA    = 0
	resolverQuestionTypeAAAA = 1
)

func performDNSQuery(
	resolveCtx context.Context,
	logWarning func(error),
	params *ResolveParameters,
	useProtocolTransform bool,
	useRandomQNameCasing bool,
	conn net.Conn,
	questionType resolverQuestionType,
	hostname string,
	responseQNameMustMatch bool) ([]net.IP, []time.Duration, time.Duration, error) {

	if useProtocolTransform {
		if params.ProtocolTransformSpec == nil ||
			params.ProtocolTransformSeed == nil {
			return nil, nil, -1, errors.TraceNew("invalid protocol transform configuration")
		}
		// miekg/dns expects conn to be a net.PacketConn or else it writes the
		// TCP length prefix
		udpConn, ok := conn.(*net.UDPConn)
		if !ok {
			return nil, nil, -1, errors.TraceNew("conn is not a *net.UDPConn")
		}
		conn = &transformDNSPacketConn{
			UDPConn:   udpConn,
			transform: params.ProtocolTransformSpec,
			seed:      params.ProtocolTransformSeed,
		}
	}

	// Convert to punycode.
	hostname, err := idna.ToASCII(hostname)
	if err != nil {
		return nil, nil, -1, errors.Trace(err)
	}

	if useRandomQNameCasing {
		hostname = common.ToRandomASCIICasing(hostname, params.RandomQNameCasingSeed)
	}

	// UDPSize sets the receive buffer to > 512, even when we don't include
	// EDNS(0), which will mitigate issues with RFC 1035 non-compliant
	// servers. See Go issue 51127.
	dnsConn := &dns.Conn{
		Conn:    conn,
		UDPSize: udpPacketBufferSize,
	}
	defer dnsConn.Close()

	// SetQuestion initializes request.MsgHdr.Id to a random value
	request := &dns.Msg{MsgHdr: dns.MsgHdr{RecursionDesired: true}}
	switch questionType {
	case resolverQuestionTypeA:
		request.SetQuestion(dns.Fqdn(hostname), dns.TypeA)
	case resolverQuestionTypeAAAA:
		request.SetQuestion(dns.Fqdn(hostname), dns.TypeAAAA)
	default:
		return nil, nil, -1, errors.TraceNew("unknown DNS request question type")
	}
	if params.IncludeEDNS0 {
		// miekg/dns: "RFC 6891, Section 6.1.1 allows the OPT record to appear
		// anywhere in the additional record section, but it's usually at the
		// end..."
		request.SetEdns0(udpPacketBufferSize, false)
	}

	startTime := time.Now()

	// Send the DNS request
	err = dnsConn.WriteMsg(request)
	if err != nil {
		return nil, nil, -1, errors.Trace(err)
	}

	// Read and process the DNS response
	var IPs []net.IP
	var TTLs []time.Duration
	var qnameMismatches int
	defer func() {
		params.setQNameMismatches(qnameMismatches)
	}()
	var lastErr error
	RTT := time.Duration(-1)
	for {

		// Stop when resolveCtx is done; the caller, ResolveIP, will also
		// close conn, which will interrupt a blocking dnsConn.ReadMsg.
		if resolveCtx.Err() != nil {

			// ResolveIP, which calls performDNSQuery, already records the
			// context error (e.g., context timeout), so instead report
			// lastErr, when present, as it may contain more useful
			// information about why a response was rejected.
			err := lastErr
			if err == nil {
				err = errors.Trace(context.Cause(resolveCtx))
			}

			return nil, nil, RTT, err
		}

		// Read a response. RTT is the elapsed time between sending the
		// request and reading the last received response.
		response, err := dnsConn.ReadMsg()
		RTT = time.Since(startTime)
		if err == nil && response.MsgHdr.Id != request.MsgHdr.Id {
			err = dns.ErrId
		}
		if err != nil {
			// Try reading again, in case the first response packet failed to
			// unmarshal or had an invalid ID. The Go resolver also does this;
			// see Go issue 13281.
			if resolveCtx.Err() == nil {
				// Only log if resolveCtx is not done; otherwise the error could
				// be due to conn being closed by ResolveIP.
				lastErr = errors.Tracef("invalid response: %v", err)
				logWarning(lastErr)
			}
			continue
		}

		if len(response.Question) != 1 || response.Question[0].Name != dns.Fqdn(hostname) {
			qnameMismatches++
			if responseQNameMustMatch {
				lastErr = errors.Tracef("unexpected QName")
				logWarning(lastErr)
				continue
			}
		}

		// Check the RCode.
		//
		// For IPv4, we expect RCodeSuccess as Psiphon will typically only
		// resolve domains that exist and have a valid IP (when this isn't
		// the case, and we retry, the overall ResolveIP and its parent dial
		// will still abort after resolveCtx is done, or RequestTimeout
		// expires for maxAttempts).
		//
		// For IPv6, we should also expect RCodeSuccess even if there is no
		// AAAA record, as long as the domain exists and has an A record.
		// However, per RFC 6147 section 5.1.2, we may receive
		// NXDOMAIN: "...some servers respond with RCODE=3 to a AAAA query
		// even if there is an A record available for that owner name. Those
		// servers are in clear violation of the meaning of RCODE 3...". In
		// this case, we coalesce NXDOMAIN into success to treat the response
		// the same as success with no AAAA record.
		//
		// All other RCodes, which are unexpected, lead to a read retry.
		if response.MsgHdr.Rcode != dns.RcodeSuccess &&
			!(questionType == resolverQuestionTypeAAAA && response.MsgHdr.Rcode == dns.RcodeNameError) {

			errMsg, ok := dns.RcodeToString[response.MsgHdr.Rcode]
			if !ok {
				errMsg = fmt.Sprintf("Rcode: %d", response.MsgHdr.Rcode)
			}
			lastErr = errors.Tracef("unexpected RCode: %v", errMsg)
			logWarning(lastErr)
			continue
		}

		// Extract all IP answers, along with corresponding TTLs for caching.
		// Perform additional validation, which may lead to another read
		// retry. However, if _any_ valid IP is found, stop reading and
		// return that result. Again, the validation is only best effort.

		checkFailed := false
		for _, answer := range response.Answer {
			haveAnswer := false
			var IP net.IP
			var TTLSec uint32
			switch questionType {
			case resolverQuestionTypeA:
				if a, ok := answer.(*dns.A); ok {
					IP = a.A
					TTLSec = a.Hdr.Ttl
					haveAnswer = true
				}
			case resolverQuestionTypeAAAA:
				if aaaa, ok := answer.(*dns.AAAA); ok {
					IP = aaaa.AAAA
					TTLSec = aaaa.Hdr.Ttl
					haveAnswer = true
				}
			}
			if !haveAnswer {
				continue
			}
			err := checkDNSAnswerIP(IP)
			if err != nil {
				checkFailed = true
				lastErr = errors.Tracef("invalid IP: %v", err)
				logWarning(lastErr)
				// Check the next answer
				continue
			}
			IPs = append(IPs, IP)
			TTLs = append(TTLs, time.Duration(TTLSec)*time.Second)
		}

		// For IPv4, an IP is expected, as noted in the comment above.
		//
		// In potential cases where we resolve a domain that has only an IPv6
		// address, the concurrent AAAA request will deliver its result to
		// ResolveIP, and that answer will be selected, so only the "await"
		// logic will delay the parent dial in that case.
		if questionType == resolverQuestionTypeA && len(IPs) == 0 && !checkFailed {
			checkFailed = true
			lastErr = errors.TraceNew("unexpected empty A response")
			logWarning(lastErr)
		}

		// Retry if there are no valid IPs and any error; if no error, this
		// may be a valid AAAA response with no IPs, in which case return the
		// result.
		if len(IPs) == 0 && checkFailed {
			continue
		}

		return IPs, TTLs, RTT, nil
	}
}

func checkDNSAnswerIP(IP net.IP) error {

	if IP == nil {
		return errors.TraceNew("IP is nil")
	}

	// Limitation: this could still be a phony/injected response, it's not
	// possible to verify with plaintext DNS, but a "bogon" IP is clearly
	// invalid.
	if common.IsBogon(IP) {
		return errors.TraceNew("IP is bogon")
	}

	// Create a temporary socket bound to the destination IP. This checks
	// thats the local host has a route to this IP. If not, we'll reject the
	// IP. This prevents selecting an IP which is guaranteed to fail to dial.
	// Use UDP as this results in no network traffic; the destination port is
	// arbitrary. The Go resolver performs a similar operation.
	//
	// Limitations:
	// - We may cache the IP and reuse it without checking routability again;
	//   the cache should be flushed when network state changes.
	// - Given that the AAAA is requested only when the host has an IPv6
	//   route, we don't expect this to often fail with a _valid_ response.
	//   However, this remains a possibility and in this case,
	//   performDNSQuery will keep awaiting a response which can trigger
	//   the "await" logic.
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: IP, Port: 443})
	if err != nil {
		return errors.Trace(err)
	}
	conn.Close()

	return nil
}

func defaultResolverLookupIP(
	ctx context.Context, hostname string, logHostnames bool) ([]net.IP, error) {

	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)

	if err != nil && !logHostnames {
		// Remove domain names from "net" error messages.
		err = common.RedactNetError(err)
	}

	if err != nil {
		return nil, errors.Trace(err)
	}

	ips := make([]net.IP, len(addrs))
	for i, addr := range addrs {
		ips[i] = addr.IP
	}

	return ips, nil
}

// transformDNSPacketConn wraps a *net.UDPConn, intercepting Write calls and
// applying the specified protocol transform.
//
// As transforms operate on strings and DNS requests are binary, the transform
// should be expressed using hex characters. The DNS packet to be written
// (input the Write) is converted to hex, transformed, and converted back to
// binary and then actually written to the UDP socket.
type transformDNSPacketConn struct {
	*net.UDPConn
	transform transforms.Spec
	seed      *prng.Seed
}

func (conn *transformDNSPacketConn) Write(b []byte) (int, error) {

	// Limitation: there is no check that a transformed packet remains within
	// the network packet MTU.

	input := hex.EncodeToString(b)
	output, err := conn.transform.ApplyString(conn.seed, input)
	if err != nil {
		return 0, errors.Trace(err)
	}
	packet, err := hex.DecodeString(output)
	if err != nil {
		return 0, errors.Trace(err)
	}

	_, err = conn.UDPConn.Write(packet)
	if err != nil {
		// In the error case, don't report bytes written as the number could
		// exceed the pre-transform length.
		return 0, errors.Trace(err)
	}

	// Report the pre-transform length as bytes written, as the caller may check
	// that the requested len(b) bytes were written.
	return len(b), nil
}
