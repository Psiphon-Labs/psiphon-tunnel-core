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

package light

import (
	"context"
	"encoding/hex"
	std_errors "errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	tls "github.com/Psiphon-Labs/psiphon-tls"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/obfuscator"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/proxyheader"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tun"
	lrucache "github.com/cognusion/go-cache-lru"
	"golang.org/x/time/rate"
)

const (
	LIGHT_PROTOCOL_TLS = "TLS"

	obfuscationKeySize              = 32
	defaultInactivityTimeout        = 60 * time.Second
	defaultUpstreamDialTimeout      = 5 * time.Second
	defaultRelayBufferSize          = 8192
	rateLimiterReapHistoryFrequency = 300 * time.Second
	rateLimiterMaxCacheEntries      = 1000000
	defaultPerIPRateLimitQuantity   = 100000
	defaultPerIPRateLimitInterval   = 1 * time.Minute
	defaultPerIPMaxConcurrent       = 50000
	defaultMaxConcurrent            = 1000000
	defaultDialFallbackDelay        = 300 * time.Millisecond
	proxyActivityUpdatePeriod       = 1 * time.Second
	defaultDNSResolverCacheMaxSize  = 256
	defaultDNSResolverCacheTTL      = 10 * time.Second
	dnsResolverCacheReapFrequency   = 1 * time.Minute
)

// ProxyConfig specifies the configuration of a light proxy.
//
// When a ProxyLimits is specified, the light proxy uses that shared limits
// state. ProxyLimitKind must also be set to either ProxyLimitKindCommon or
// ProxyLimitKindPersonal, indicating which class of ProxyLimits values the
// light proxy should use.
//
// When ProxyLimits is nil, ProxyConfig limit parameters are used instead.
type ProxyConfig struct {
	Protocol                                      string              `json:",omitempty"`
	ProviderID                                    string              `json:",omitempty"`
	ListenAddresses                               []string            `json:",omitempty"`
	DialAddressIPv4                               string              `json:",omitempty"`
	DialAddressIPv6                               string              `json:",omitempty"`
	ObfuscationKey                                string              `json:",omitempty"`
	TLSCertificate                                []byte              `json:",omitempty"`
	TLSPrivateKey                                 []byte              `json:",omitempty"`
	PassthroughAddress                            string              `json:",omitempty"`
	AllowedDestinations                           []string            `json:",omitempty"`
	InactivityTimeout                             string              `json:",omitempty"`
	UpstreamDialTimeout                           string              `json:",omitempty"`
	RelayBufferSize                               int                 `json:",omitempty"`
	PerIPRateLimitQuantity                        *int                `json:",omitempty"`
	PerIPRateLimitInterval                        string              `json:",omitempty"`
	PerIPMaxConcurrent                            *int                `json:",omitempty"`
	MaxConcurrent                                 *int                `json:",omitempty"`
	LimitUpstreamBytesPerSecond                   int                 `json:",omitempty"`
	LimitDownstreamBytesPerSecond                 int                 `json:",omitempty"`
	DialFallbackDelay                             string              `json:",omitempty"`
	DNSResolverCacheMaxSize                       *int                `json:",omitempty"`
	DNSResolverCacheTTL                           string              `json:",omitempty"`
	SplitUpstreamInterfaceName                    string              `json:",omitempty"`
	SplitDownstreamInterfaceName                  string              `json:",omitempty"`
	ProxyProtocolHeaderMACKeys                    map[string]string   `json:",omitempty"`
	ProxyProtocolHeaderTargetDestinationAddresses map[string][]string `json:",omitempty"`
	ProxyLimits                                   *common.ProxyLimits `json:"-"`
	ProxyLimitKind                                ProxyLimitKind      `json:"-"`
	LogDestinationAddresses                       bool                `json:",omitempty"`
	AllowBogons                                   bool                `json:",omitempty"`
	EmitActivity                                  bool                `json:",omitempty"`
	EnableDebugLogs                               bool                `json:",omitempty"`
}

type ProxyLimitKind int

const (
	ProxyLimitKindNone ProxyLimitKind = iota
	ProxyLimitKindCommon
	ProxyLimitKindPersonal
)

// ConnectionStats are the proxy connection stats reported to
// ProxyEventReceiver at the end of connection. If the connection failed to
// fully establish, the ConnectionFailure reports the reason. Values that the
// clients sends in the light header will be zero values when the light
// header was not read successfully, and the proxy's phase-completed
// timestamps will be zero values when the phase was not completed.
type ConnectionStats struct {
	ProxyID                     string
	ProxyProviderID             string
	ProxyGeoIPData              common.GeoIPData
	ProxyConnectionNum          int64
	ClientGeoIPData             common.GeoIPData
	SponsorID                   string
	ClientPlatform              string
	ClientBuildRev              string
	DeviceRegion                string
	SessionID                   string
	ProxyEntryTracker           int64
	NetworkType                 string
	ClientConnectionNum         int64
	DestinationAddress          string
	TLSProfile                  string
	SNI                         string
	TLSClientHelloFragmented    bool
	TLSClientHelloPadding       int
	TLSDidResume                bool
	ClientTCPDuration           time.Duration
	ClientTLSDuration           time.Duration
	ProxyCompletedTCP           time.Time
	ProxyCompletedTLS           time.Time
	ProxyCompletedLightHeader   time.Time
	ProxyCompletedUpstreamDNS   time.Time
	ProxyCompletedUpstreamTCP   time.Time
	UpstreamDNSCached           bool
	ProxyProtocolHeaderAdded    bool
	ProxyProtocolHeaderReplaced bool
	BytesRead                   int64
	BytesWritten                int64
	Failure                     string
}

// ActivityStats are proxy activity stats reported to ProxyEventReceiver.
type ActivityStats struct {
	ProxyID                string
	ProxyProviderID        string
	BytesUp                int64
	BytesDown              int64
	BytesDuration          time.Duration
	CurrentConnectionCount int64
	RegionActivity         map[string]RegionActivityStats
}

// RegionActivityStats are per-region proxy activity stats.
type RegionActivityStats struct {
	BytesUp                int64
	BytesDown              int64
	CurrentConnectionCount int64
}

// ProxyEventReceiver receives event callbacks from a light proxy, and handles
// logging and stats shipping. ProxyEventReceiver callbacks should not block
// on processing and instead should dispatch any work that is to be performed.
type ProxyEventReceiver interface {
	Listening(address string)
	Paused()
	Resumed()

	// Accepted indicates that a new connection has been accepted. The outcome
	// will be reported in a Connection event.
	Accepted()

	// Rejected indicates that a connection was rejected in the paused state.
	// There will be no Connection event.
	Rejected()

	// Connection reports the outcome and statistics for a completed connection.
	//
	// The ProxyEventReceiver may assume ownership of stats. The Proxy caller
	// will not access it after passing it to Connection.
	Connection(stats *ConnectionStats)
	Activity(stats *ActivityStats)

	IrregularConnection(
		proxyID string,
		geoIPData common.GeoIPData,
		irregularity string)

	DebugLog(proxyID string, message string)
	InfoLog(proxyID string, message string)
	WarningLog(proxyID string, message string)
	ErrorLog(proxyID string, message string)
}

// LookupGeoIP is a callback that provides GeoIP lookup service.
type LookupGeoIP func(IP string) common.GeoIPData

// Proxy is a lightweight proxy.
type Proxy struct {
	config                     *ProxyConfig
	lookupGeoIP                LookupGeoIP
	eventReceiver              ProxyEventReceiver
	ID                         string
	proxyGeoIPData             common.GeoIPData
	tlsConfig                  *tls.Config
	obfuscatorSeedHistory      *obfuscator.SeedHistory
	allowedDestinations        common.StringLookup
	proxyProtocolHeaderConfigs map[string]proxyProtocolHeaderConfig
	inactivityTimeout          time.Duration
	upstreamDialTimeout        time.Duration
	relayBufferSize            int
	relayBufferPool            sync.Pool
	rateLimitQuantity          int
	rateLimitInterval          time.Duration
	perIPMaxConcurrent         int
	dialFallbackDelay          time.Duration

	listenConfig *net.ListenConfig
	dialer       *net.Dialer

	limitsMutex                sync.Mutex
	perIPConcurrentConnections map[string]int
	rateLimiters               *lrucache.Cache
	proxyLimits                *common.ProxyLimits
	proxyLimitKind             ProxyLimitKind

	dnsResolver *net.Resolver
	dnsCache    *lrucache.Cache

	connectionNumber atomic.Int64
	paused           atomic.Bool

	activityBytesUp        atomic.Int64
	activityBytesDown      atomic.Int64
	currentConnectionCount atomic.Int64

	activityRegionsMutex sync.Mutex
	regionActivity       map[string]*regionActivity
}

type regionActivity struct {
	bytesUp                atomic.Int64
	bytesDown              atomic.Int64
	currentConnectionCount atomic.Int64
}

// NewProxy initializes a Proxy. ProxyConfig, LookupGeoIP, and
// ProxyEventReceiver are required.
func NewProxy(
	config *ProxyConfig,
	lookupGeoIP LookupGeoIP,
	eventReceiver ProxyEventReceiver) (*Proxy, error) {

	if config == nil || lookupGeoIP == nil || eventReceiver == nil {
		return nil, errors.TraceNew("invalid config")
	}

	if config.Protocol != LIGHT_PROTOCOL_TLS {
		return nil, errors.TraceNew("unsupported proxy protocol")
	}

	if len(config.ListenAddresses) == 0 {
		return nil, errors.TraceNew("missing listen addresses")
	}

	for _, listenAddress := range config.ListenAddresses {
		if listenAddress == "" {
			return nil, errors.TraceNew("missing listen address")
		}
	}

	if config.ObfuscationKey == "" {
		return nil, errors.TraceNew("missing obfuscation key")
	}

	// In the TLS light proxy protocol, the passthrough message serves as
	// authentication that the client has the proxy entry and knows the
	// obfuscation key, so passthrough must be enabled.
	//
	// Future enhancement: support enabling passthrough mode without an actual
	// upstream passthrough address?

	if config.PassthroughAddress == "" {
		return nil, errors.TraceNew("missing passthrough address")
	}

	normalizedAllowedDestinations := make([]string, len(config.AllowedDestinations))
	for i, address := range config.AllowedDestinations {
		var err error
		normalizedAllowedDestinations[i], err = normalizeDestinationAddress(address)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	proxyProtocolHeaderConfigs, err := prepareProxyProtocolHeaderConfigs(
		config.ProxyProtocolHeaderMACKeys,
		config.ProxyProtocolHeaderTargetDestinationAddresses)
	if err != nil {
		return nil, errors.Trace(err)
	}

	inactivityTimeout := defaultInactivityTimeout
	if config.InactivityTimeout != "" {
		var err error
		inactivityTimeout, err = time.ParseDuration(config.InactivityTimeout)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	upstreamDialTimeout := defaultUpstreamDialTimeout
	if config.UpstreamDialTimeout != "" {
		var err error
		upstreamDialTimeout, err = time.ParseDuration(config.UpstreamDialTimeout)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	relayBufferSize := defaultRelayBufferSize
	if config.RelayBufferSize > 0 {
		relayBufferSize = config.RelayBufferSize
	}

	if (config.PerIPRateLimitQuantity != nil) != (config.PerIPRateLimitInterval != "") ||
		(config.PerIPRateLimitQuantity != nil && *config.PerIPRateLimitQuantity < 0) ||
		(config.PerIPMaxConcurrent != nil && *config.PerIPMaxConcurrent < 0) ||
		(config.MaxConcurrent != nil && *config.MaxConcurrent < 0) ||
		config.LimitUpstreamBytesPerSecond < 0 ||
		config.LimitDownstreamBytesPerSecond < 0 {
		return nil, errors.TraceNew("invalid limits")
	}

	rateLimitQuantity := defaultPerIPRateLimitQuantity
	if config.PerIPRateLimitQuantity != nil {
		rateLimitQuantity = *config.PerIPRateLimitQuantity
	}

	rateLimitInterval := defaultPerIPRateLimitInterval
	if config.PerIPRateLimitInterval != "" {
		var err error
		rateLimitInterval, err = time.ParseDuration(config.PerIPRateLimitInterval)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	perIPMaxConcurrent := defaultPerIPMaxConcurrent
	if config.PerIPMaxConcurrent != nil {
		perIPMaxConcurrent = *config.PerIPMaxConcurrent
	}

	maxConcurrent := defaultMaxConcurrent
	if config.MaxConcurrent != nil {
		maxConcurrent = *config.MaxConcurrent
	}

	dialFallbackDelay := defaultDialFallbackDelay
	if config.DialFallbackDelay != "" {
		var err error
		dialFallbackDelay, err = time.ParseDuration(config.DialFallbackDelay)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	dnsResolverCacheMaxSize := defaultDNSResolverCacheMaxSize
	if config.DNSResolverCacheMaxSize != nil {
		if *config.DNSResolverCacheMaxSize < 0 {
			return nil, errors.TraceNew("invalid max cache size")
		}
		dnsResolverCacheMaxSize = *config.DNSResolverCacheMaxSize
	}

	dnsResolverCacheTTL := defaultDNSResolverCacheTTL
	if config.DNSResolverCacheTTL != "" {
		var err error
		dnsResolverCacheTTL, err = time.ParseDuration(config.DNSResolverCacheTTL)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	listenConfig := &net.ListenConfig{}
	dialer := &net.Dialer{}

	splitInterfaceMode := config.SplitUpstreamInterfaceName != "" ||
		config.SplitDownstreamInterfaceName != ""
	if splitInterfaceMode {
		if !tun.IsBindToDeviceSupported() {
			return nil, errors.TraceNew("split interface is not supported")
		}
		if config.SplitUpstreamInterfaceName != "" &&
			config.SplitDownstreamInterfaceName == config.SplitUpstreamInterfaceName {
			return nil, errors.TraceNew(
				"SplitDownstreamInterfaceName must differ from SplitUpstreamInterfaceName")
		}

		upstreamInterfaceName := config.SplitUpstreamInterfaceName
		downstreamInterfaceName := config.SplitDownstreamInterfaceName
		if upstreamInterfaceName == "" {
			upstreamInterfaceName = common.FindInterfaceExcluding(downstreamInterfaceName)
		}
		if downstreamInterfaceName == "" {
			downstreamInterfaceName = common.FindInterfaceExcluding(upstreamInterfaceName)
		}
		if upstreamInterfaceName == "" {
			return nil, errors.TraceNew(
				"unable to determine upstream interface; set SplitUpstreamInterfaceName")
		}
		if downstreamInterfaceName == "" {
			return nil, errors.TraceNew(
				"unable to determine downstream interface; set SplitDownstreamInterfaceName")
		}

		listenConfig.Control = makeBindToDeviceControl(downstreamInterfaceName)
		dialer.Control = makeBindToDeviceControl(upstreamInterfaceName)
	}

	// Initialize the DNS resolver and optional cache following the pattern in
	// psiphon/server.sshClient.getDNSResolver. See additional comments in
	// that function.
	//
	// The light proxy is intended for use by Psiphon Library apps which will
	// largely all send traffic to the same small set of domains in allowed
	// destinations. The standard library net.Resolver with "singleflight"
	// functionality and a cache are shared across all light proxy
	// connections as timing leaks are not considered a threat in this use
	// case.
	//
	// Since actual DNS response TTLs are not exposed by net.Resolver, the
	// cache should be configured with a conservative TTL -- 10s of seconds.
	//
	// PreferGo, equivalent to GODEBUG=netdns=go, is specified in order to
	// avoid any cases where Go's resolver fails over to the cgo-based
	// resolver while will consume an OS thread.

	dnsResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, address)
			return conn, errors.Trace(err)
		},
	}

	// Route hostname lookups performed by the dialer itself, which happens
	// when PassthroughAddress is a hostname, through dnsResolver to ensure
	// dialer.Control is applied. Limitation: currently this doesn't use the
	// DNS cache.
	dialer.Resolver = dnsResolver

	var dnsCache *lrucache.Cache
	if dnsResolverCacheMaxSize > 0 && dnsResolverCacheTTL > 0 {
		dnsCache = lrucache.NewWithLRU(
			dnsResolverCacheTTL,
			dnsResolverCacheReapFrequency,
			dnsResolverCacheMaxSize)
	}

	host, _, err := net.SplitHostPort(config.DialAddressIPv4)
	if err != nil {
		return nil, errors.Trace(err)
	}
	proxyIP := net.ParseIP(host)
	if proxyIP == nil {
		return nil, errors.TraceNew("invalid IP")
	}
	proxyGeoIPData := lookupGeoIP(proxyIP.String())

	tlsCertificate, err := tls.X509KeyPair(
		config.TLSCertificate,
		config.TLSPrivateKey)
	if err != nil {
		return nil, errors.Trace(err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCertificate},
		NextProtos:   []string{"h2", "http/1.1"},
		// Use min TLS 1.3 so cert is not plaintext on the wire.
		MinVersion: tls.VersionTLS13,
	}

	proxyLimitKind := config.ProxyLimitKind
	proxyLimits := config.ProxyLimits
	if proxyLimits == nil {

		// If no shared limits are provided, instantiate internal limits from
		// config fields. The config-driven light proxy uses common limits.

		if proxyLimitKind != ProxyLimitKindNone {
			return nil, errors.TraceNew("invalid ProxyLimitKind")
		}

		proxyLimitKind = ProxyLimitKindCommon
		proxyLimits, err = newProxyLimitsFromConfig(config, maxConcurrent)
		if err != nil {
			return nil, errors.Trace(err)
		}

	} else if proxyLimitKind != ProxyLimitKindCommon &&
		proxyLimitKind != ProxyLimitKindPersonal {

		return nil, errors.TraceNew("invalid ProxyLimitKind")
	}

	proxy := &Proxy{
		config:                     config,
		lookupGeoIP:                lookupGeoIP,
		eventReceiver:              newRedactingProxyEventReceiver(eventReceiver),
		ID:                         makeProxyID(config.DialAddressIPv4, config.ObfuscationKey),
		proxyGeoIPData:             proxyGeoIPData,
		tlsConfig:                  tlsConfig,
		obfuscatorSeedHistory:      obfuscator.NewSeedHistory(nil),
		allowedDestinations:        common.NewStringLookup(normalizedAllowedDestinations),
		proxyProtocolHeaderConfigs: proxyProtocolHeaderConfigs,
		inactivityTimeout:          inactivityTimeout,
		upstreamDialTimeout:        upstreamDialTimeout,
		relayBufferSize:            relayBufferSize,
		relayBufferPool: sync.Pool{New: func() any {
			b := make([]byte, relayBufferSize)
			return &b
		}},
		rateLimitQuantity:  rateLimitQuantity,
		rateLimitInterval:  rateLimitInterval,
		perIPMaxConcurrent: perIPMaxConcurrent,
		proxyLimits:        proxyLimits,
		proxyLimitKind:     proxyLimitKind,
		dnsResolver:        dnsResolver,
		dnsCache:           dnsCache,
		listenConfig:       listenConfig,
		dialer:             dialer,
		dialFallbackDelay:  dialFallbackDelay,

		perIPConcurrentConnections: make(map[string]int),
		rateLimiters: lrucache.NewWithLRU(
			0,
			rateLimiterReapHistoryFrequency,
			rateLimiterMaxCacheEntries),
		regionActivity: make(map[string]*regionActivity),
	}

	tlsConfig.PassthroughAddress = config.PassthroughAddress
	tlsConfig.PassthroughDialer = proxy.dialer.Dial

	tlsConfig.PassthroughVerifyMessage = func(message []byte) bool {
		return obfuscator.VerifyTLSPassthroughMessage(
			true,
			config.ObfuscationKey,
			message)
	}

	tlsConfig.PassthroughLogInvalidMessage = func(clientIP string) {
		geoIPData := proxy.lookupGeoIP(clientIP)
		proxy.eventReceiver.IrregularConnection(
			proxy.ID, geoIPData, "invalid passthrough message")
	}

	tlsConfig.PassthroughHistoryAddNew = func(
		clientIP string,
		clientRandom []byte) bool {

		// See comments in psiphon/server.TLSTunnelServer.makeTLSTunnelConfig.
		strictMode := true
		TTL := obfuscator.TLS_PASSTHROUGH_HISTORY_TTL

		ok, logFields := proxy.obfuscatorSeedHistory.AddNewWithTTL(
			strictMode,
			clientIP,
			"client-random",
			clientRandom,
			TTL)
		if logFields != nil {
			// Future enhancement: log the fields in logFields, which
			// provide some characterization of the potential prober.
			geoIPData := proxy.lookupGeoIP(clientIP)
			proxy.eventReceiver.IrregularConnection(
				proxy.ID, geoIPData, "duplicate passthrough message")
		}
		return ok
	}

	return proxy, nil
}

func newProxyLimitsFromConfig(
	config *ProxyConfig,
	maxConcurrent int) (*common.ProxyLimits, error) {

	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrent
	}

	return common.NewProxyLimits(&common.ProxyLimitsConfig{
		MaxCommonClients:               maxConcurrent,
		CommonUpstreamBytesPerSecond:   config.LimitUpstreamBytesPerSecond,
		CommonDownstreamBytesPerSecond: config.LimitDownstreamBytesPerSecond,
	})
}

// Pause sets the paused state, in which new proxy connections are rejected.
// This is intended for load limiting.
func (proxy *Proxy) Pause() {
	proxy.paused.Store(true)
	proxy.eventReceiver.Paused()
}

// Resume unsets the paused state.
func (proxy *Proxy) Resume() {
	proxy.paused.Store(false)
	proxy.eventReceiver.Resumed()
}

// SetLimits sets new values for MaxConcurrent, LimitUpstreamBytesPerSecond,
// and LimitDownstreamBytesPerSecond. If MaxConcurrent is nil or 0, a default
// value is used. These values will be applied rolling forward; no active
// connections are closed and the rate limits for active connections do not
// change.
func (proxy *Proxy) SetLimits(
	maxConcurrent *int,
	limitUpstreamBytesPerSecond int,
	limitDownstreamBytesPerSecond int) error {

	if (maxConcurrent != nil && *maxConcurrent < 0) ||
		limitUpstreamBytesPerSecond < 0 ||
		limitDownstreamBytesPerSecond < 0 {
		return errors.TraceNew("invalid limits")
	}

	if proxy.config.ProxyLimits != nil {
		return errors.TraceNew("SetLimits cannot be used with shared ProxyLimits")
	}

	newMaxConcurrent := defaultMaxConcurrent
	if maxConcurrent != nil && *maxConcurrent > 0 {
		newMaxConcurrent = *maxConcurrent
	}

	return errors.Trace(proxy.proxyLimits.SetCommonLimits(
		newMaxConcurrent,
		limitUpstreamBytesPerSecond,
		limitDownstreamBytesPerSecond))
}

// Run runs the proxy until the specified context is done.
//
// Only one concurrent Run call is supported.
func (proxy *Proxy) Run(ctx context.Context) error {

	// Future enhancement: use psiphon/server.newTCPListenerWithBPF.
	listeners := make([]net.Listener, 0, len(proxy.config.ListenAddresses))
	closeListeners := func() {
		for _, listener := range listeners {
			listener.Close()
		}
	}

	for _, listenAddress := range proxy.config.ListenAddresses {
		listener, err := proxy.listenConfig.Listen(
			context.Background(), "tcp", listenAddress)
		if err != nil {
			closeListeners()
			return errors.Trace(err)
		}
		listeners = append(listeners, listener)
	}

	for _, listener := range listeners {
		proxy.eventReceiver.Listening(listener.Addr().String())
	}

	waitGroup := new(sync.WaitGroup)

	if proxy.config.EmitActivity {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			proxy.activityUpdate(ctx)
		}()
	}

	for _, listener := range listeners {
		listener := listener
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for {
				conn, err := listener.Accept()
				if err != nil {
					if ctx.Err() != nil {
						break
					}
					proxy.eventReceiver.WarningLog(
						proxy.ID, errors.Trace(err).Error())
					continue
				}
				if proxy.paused.Load() {

					// Immediately close the accepted TCP connection when paused.
					// Clients will observe a fast failure.
					//
					// Future enhancement: close the listener while paused, to
					// avoid the load of accepting TCP connections.
					// Alternatively, for certain proxy load patterns it may be
					// more optimal to accept the connection and, rather than
					// immediately close it, enqueue for a short time in
					// anticipation of resume.

					conn.Close()
					proxy.eventReceiver.Rejected() // Blocks accept loop
					continue
				}
				waitGroup.Add(1)
				go func(conn net.Conn) {
					defer waitGroup.Done()
					proxy.eventReceiver.Accepted()
					err := proxy.handleConn(ctx, conn)
					if err != nil && ctx.Err() == nil {
						proxy.eventReceiver.WarningLog(
							proxy.ID, errors.Trace(err).Error())
					}
				}(conn)
			}
		}()
	}

	<-ctx.Done()
	closeListeners()
	waitGroup.Wait()

	return nil
}

func (proxy *Proxy) handleConn(ctx context.Context, conn net.Conn) (retErr error) {

	connToClose := conn
	defer func() {
		connToClose.Close()
	}()

	var geoIPData common.GeoIPData
	completedTCP := time.Now().UTC()
	var completedTLS time.Time
	var clientSNI string
	var tlsClientHelloFragmented bool
	var tlsClientHelloPadding int
	var tlsDidResume bool
	bytesCounter := &bytesCounter{}
	if proxy.config.EmitActivity {
		bytesCounter.activityProxy = proxy
	}
	var completedLightHeader time.Time
	var header *lightHeader
	var sponsorID string
	var normalizedDestinationAddress string
	var completedUpstreamDNS time.Time
	var completedUpstreamTCP time.Time
	var upstreamDNSCached bool
	var proxyProtocolHeaderAdded bool
	var proxyProtocolHeaderReplaced bool

	connectionNum := proxy.connectionNumber.Add(1)

	// Connection stats are emitted on connection end, including for any
	// failures after this point.
	defer func() {

		var clientPlatform, clientBuildRev string
		var deviceRegion, sessionID, networkType, tlsProfile string
		var proxyEntryTracker, clientConnectionNum int64
		var clientTCPDuration, clientTLSDuration time.Duration

		if header != nil {
			clientPlatform = decodeClientPlatform(header.ClientPlatform)
			clientBuildRev = hex.EncodeToString(header.ClientBuildRev)
			deviceRegion = header.DeviceRegion
			sessionID = hex.EncodeToString(header.SessionID)
			proxyEntryTracker = header.ProxyEntryTracker
			networkType = decodeNetworkType(header.NetworkType)
			clientConnectionNum = header.ConnectionNum
			tlsProfile = decodeTLSProfile(header.TLSProfile)
			clientTCPDuration = time.Duration(header.TCPDuration)
			clientTLSDuration = time.Duration(header.TLSDuration)
		}

		failure := ""
		if retErr != nil {
			failure = retErr.Error()
		}

		destinationAddress := ""
		if proxy.config.LogDestinationAddresses {
			destinationAddress = normalizedDestinationAddress
		}

		stats := &ConnectionStats{
			ProxyID:                     proxy.ID,
			ProxyProviderID:             proxy.config.ProviderID,
			ProxyGeoIPData:              proxy.proxyGeoIPData,
			ProxyConnectionNum:          connectionNum,
			ClientGeoIPData:             geoIPData,
			SponsorID:                   sponsorID,
			ClientPlatform:              clientPlatform,
			ClientBuildRev:              clientBuildRev,
			DeviceRegion:                deviceRegion,
			SessionID:                   sessionID,
			ProxyEntryTracker:           proxyEntryTracker,
			NetworkType:                 networkType,
			ClientConnectionNum:         clientConnectionNum,
			DestinationAddress:          destinationAddress,
			TLSProfile:                  tlsProfile,
			SNI:                         clientSNI,
			TLSClientHelloFragmented:    tlsClientHelloFragmented,
			TLSClientHelloPadding:       tlsClientHelloPadding,
			TLSDidResume:                tlsDidResume,
			ClientTCPDuration:           clientTCPDuration,
			ClientTLSDuration:           clientTLSDuration,
			ProxyCompletedTCP:           completedTCP,
			ProxyCompletedTLS:           completedTLS,
			ProxyCompletedLightHeader:   completedLightHeader,
			ProxyCompletedUpstreamDNS:   completedUpstreamDNS,
			ProxyCompletedUpstreamTCP:   completedUpstreamTCP,
			UpstreamDNSCached:           upstreamDNSCached,
			ProxyProtocolHeaderAdded:    proxyProtocolHeaderAdded,
			ProxyProtocolHeaderReplaced: proxyProtocolHeaderReplaced,
			BytesRead:                   bytesCounter.bytesRead.Load(),
			BytesWritten:                bytesCounter.bytesWritten.Load(),
			Failure:                     failure,
		}

		// The event receiver assumes ownership of stats; do not access after
		// this point.
		proxy.eventReceiver.Connection(stats)
	}()

	clientIP, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return errors.Trace(err)
	}

	geoIPData = proxy.lookupGeoIP(clientIP)

	if proxy.config.EmitActivity {

		proxy.currentConnectionCount.Add(1)
		defer proxy.currentConnectionCount.Add(-1)

		activityRegion := proxy.getOrCreateRegionActivity(geoIPData.Country)
		if activityRegion != nil {
			bytesCounter.activityRegion = activityRegion
			defer func() {
				activityRegion.currentConnectionCount.Add(-1)
			}()
		}
	}

	activityConn, err := common.NewActivityMonitoredConn(
		conn,
		proxy.inactivityTimeout,
		false,
		nil,
		bytesCounter)
	if err != nil {
		return errors.Trace(err)
	}

	// For TLS passthrough, the underlying client conn wrapped with tls.Server
	// must not be closed when passthrough is invoked. psiphon-tls will spawn
	// a goroutine to relay traffic between the underlying client conn and
	// passthrough destination. It's safe to close tlsConn when tls.Handshake
	// fails, as the underlying client conn is detached in the passthrough
	// case. connToClose tracks the correct client conn to close.
	//
	// Limitations:
	//
	// - The handleCtx AfterFunc, triggered at the end of Run, will interrupt
	//   any TLS handshake in progress, regardless of whether it may be a
	//   passthrough candidate.
	//
	// - Early error returns still close the actual underlying client conn
	//   before connToClose is set to tlsConn, which is observable to a
	//   passthrough client. However, all early returns should be
	//   internal/unexpected error conditions.
	//
	// - Passthrough relays may run indefinitely, even beyond Proxy.Run. This
	//   is the intended design; see psiphon-tls.Conn.serverHandshake. To
	//   support this, the activityConn inactivity timeout is deactivated
	//   when the TLS handshake fails. In addition, passthrough bytes
	//   continue to be counted for the lifetime of the passtrhough relay.

	handleCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	unassociateAfter := context.AfterFunc(handleCtx, func() {
		// Interrupt TLS handshake, light header read.
		activityConn.Close()
	})
	defer unassociateAfter()

	tlsConn := tls.Server(activityConn, proxy.tlsConfig)
	connToClose = tlsConn

	err = tlsConn.Handshake()
	connectionMetrics := tlsConn.ConnectionMetrics()
	tlsClientHelloFragmented = connectionMetrics.ClientHelloFragmented
	tlsClientHelloPadding = connectionMetrics.ClientHelloPaddingLength
	if err != nil {

		// Disable the inactivity timeout to support the passthrough relay
		// case. For genuine handshake failures this is inconsequential, as
		// the conn is closed on return.
		_ = activityConn.SetInactivityTimeout(0)

		return errors.Trace(err)
	}

	// Future enhancement: it's possible to record the SNI even if the TLS
	// handshake fails, via tlsConfig.GetConfigForClient. This requires a
	// tlsConfig.Clone(); note that there's currently a bug in
	// psiphon-tls.Config.Clone, where it fails to copy the passthrough
	// configuration.

	completedTLS = time.Now().UTC()
	connectionState := tlsConn.ConnectionState()
	clientSNI = connectionState.ServerName
	tlsDidResume = connectionState.DidResume

	lightConn := newLightConn(tlsConn, nil)

	header, err = lightConn.readHeader()
	if err != nil {
		return errors.Trace(err)
	}

	// The sponsor ID is uppercase by convention; the case lost in header
	// binary encoding.
	sponsorID = strings.ToUpper(hex.EncodeToString(header.SponsorID))

	unassociateAfter()

	completedLightHeader = time.Now().UTC()

	// Apply limits after reading the header so that the ConnectionFailure
	// will be accompanied by client characteristics such as sponsor ID. A
	// later enforcement also means the client is authenticated as having the
	// obfuscation key, and a prober behind shared NAT can't consume limits.

	limitIP := common.GetRateLimitIP(clientIP)
	err = proxy.applyRateLimit(limitIP)
	if err != nil {
		return errors.Trace(err)
	}

	// Check light-local per-IP capacity before acquiring shared capacity, so
	// a connection rejected by the local cap does not temporarily consume a
	// shared slot.
	err = proxy.takePerIPMaxConcurrent(limitIP)
	if err != nil {
		return errors.Trace(err)
	}
	defer proxy.replacePerIPMaxConcurrent(limitIP)

	releaseProxyLimit, err := proxy.acquireProxyLimit()
	if err != nil {
		return errors.Trace(err)
	}
	defer releaseProxyLimit()

	normalizedDestinationAddress, err = normalizeDestinationAddress(header.DestinationAddress)
	if err != nil {
		return errors.Trace(err)
	}
	if proxy.allowedDestinations.Len() > 0 &&
		!proxy.allowedDestinations.Contains(normalizedDestinationAddress) {

		return errors.TraceNew("disallowed destination")
	}

	dialCtx, dialCancel := context.WithTimeout(ctx, proxy.upstreamDialTimeout)
	defer dialCancel()

	// In addition to resolving domains, proxy.resolve also enforces the
	// IsBogon check against direct or indirect (resolved) bogon IP dials.

	upstreamAddrs, cached, err := proxy.resolve(dialCtx, normalizedDestinationAddress)
	if err != nil {
		err = common.RedactNetError(err)
		return errors.Trace(err)
	}

	upstreamDNSCached = cached
	completedUpstreamDNS = time.Now().UTC()

	upstreamConn, err := netDialParallel(
		dialCtx, proxy.dialFallbackDelay, upstreamAddrs, proxy.dialer)
	if err != nil {
		err = common.RedactNetError(err)
		return errors.Trace(err)
	}
	dialCancel()

	completedUpstreamTCP = time.Now().UTC()

	defer upstreamConn.Close()

	unassociateAfter = context.AfterFunc(handleCtx, func() {
		// Interrupt relay (or PROXY protocol read).
		lightConn.Close()
		upstreamConn.Close()
	})
	defer unassociateAfter()

	proxyProtocolHeaderConfig, addProxyProtocolHeader :=
		proxy.proxyProtocolHeaderConfigs[sponsorID]
	if addProxyProtocolHeader {
		addProxyProtocolHeader =
			proxyProtocolHeaderConfig.targetDestinationAddresses.Contains(
				normalizedDestinationAddress)
	}

	if addProxyProtocolHeader {

		// Add the PROXY protocol header with the original client IP, using a
		// MAC to authenticate the header values. Any existing PROXY protocol
		// header will be replaced with this new header.
		//
		// Limitation: AddOrReplaceProxyProtocolHeader attempts to first read
		// any PROXY protocol sent by the client, and as a result is not
		// compatible with server-first network protocols. See also the PROXY
		// v1/v2 signature limitations in
		// proxyheader.AddOrReplaceProxyProtocolHeader.

		sourceTCPAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
		if !ok {
			return errors.TraceNew("unexpected client address type")
		}

		upstreamTCPAddr, ok := upstreamConn.RemoteAddr().(*net.TCPAddr)
		if !ok {
			return errors.TraceNew("unexpected upstream address type")
		}

		macKey := proxyProtocolHeaderConfig.macKey
		wireHeader, err := proxyheader.MakeProxyProtocolHeader(
			macKey[:proxyheader.ProxyProtocolHeaderKeyIDSize],
			macKey[proxyheader.ProxyProtocolHeaderKeyIDSize:],
			sourceTCPAddr.IP,
			upstreamTCPAddr.IP,
			upstreamTCPAddr.Port)
		if err != nil {
			return errors.Trace(err)
		}

		_, replaced, err := proxyheader.AddOrReplaceProxyProtocolHeader(
			lightConn,
			upstreamConn,
			wireHeader)
		if err != nil {
			return errors.Trace(err)
		}
		if replaced {
			proxyProtocolHeaderReplaced = true
		} else {
			proxyProtocolHeaderAdded = true
		}
	}

	rateLimits, apply := proxy.getTrafficRateLimits()
	if apply {

		// Throttling does not apply to the TLS handshake, reading the light
		// proxy header, or writing the PROXY protocol header, just the relay.

		upstreamConn = common.NewThrottledConn(
			upstreamConn,
			true,
			rateLimits)
	}

	copyWithRelayBuffer := func(dst net.Conn, src net.Conn) (int64, error) {
		relayBuffer := proxy.relayBufferPool.Get().(*[]byte)
		defer proxy.relayBufferPool.Put(relayBuffer)
		return common.CopyBuffer(dst, src, *relayBuffer)
	}

	relayWaitGroup := new(sync.WaitGroup)

	relayWaitGroup.Add(1)
	go func() {
		defer relayWaitGroup.Done()
		_, err := copyWithRelayBuffer(lightConn, upstreamConn)
		if err != nil && ctx.Err() == nil {
			// Debug since errors such as "connection reset by peer" occur
			// during normal operation
			if proxy.config.EnableDebugLogs {
				err = common.RedactNetError(err)
				proxy.eventReceiver.DebugLog(proxy.ID, errors.Trace(err).Error())
			}
		}
		lightConn.Close()
	}()

	_, err = copyWithRelayBuffer(upstreamConn, lightConn)
	if err != nil && ctx.Err() == nil {
		if proxy.config.EnableDebugLogs {
			err = common.RedactNetError(err)
			proxy.eventReceiver.DebugLog(proxy.ID, errors.Trace(err).Error())
		}
	}
	upstreamConn.Close()

	cancel()
	relayWaitGroup.Wait()

	return nil
}

type bytesCounter struct {
	bytesRead      atomic.Int64
	bytesWritten   atomic.Int64
	activityProxy  *Proxy
	activityRegion *regionActivity
}

func (counter *bytesCounter) UpdateProgress(bytesRead, bytesWritten, _ int64) {
	counter.bytesRead.Add(bytesRead)
	counter.bytesWritten.Add(bytesWritten)
	if counter.activityProxy != nil {
		counter.activityProxy.activityBytesUp.Add(bytesRead)
		counter.activityProxy.activityBytesDown.Add(bytesWritten)
	}
	if counter.activityRegion != nil {
		counter.activityRegion.bytesUp.Add(bytesRead)
		counter.activityRegion.bytesDown.Add(bytesWritten)
	}
}

func (proxy *Proxy) getOrCreateRegionActivity(region string) *regionActivity {
	if region == "" {
		return nil
	}

	proxy.activityRegionsMutex.Lock()
	defer proxy.activityRegionsMutex.Unlock()

	stats, ok := proxy.regionActivity[region]
	if !ok {
		stats = &regionActivity{}
		proxy.regionActivity[region] = stats
	}
	stats.currentConnectionCount.Add(1)
	return stats
}

func (proxy *Proxy) snapshotAndResetRegionActivity() map[string]RegionActivityStats {
	proxy.activityRegionsMutex.Lock()
	defer proxy.activityRegionsMutex.Unlock()

	result := make(map[string]RegionActivityStats, len(proxy.regionActivity))
	var regionsToDelete []string
	for region, stats := range proxy.regionActivity {
		snapshot := RegionActivityStats{
			BytesUp:                stats.bytesUp.Swap(0),
			BytesDown:              stats.bytesDown.Swap(0),
			CurrentConnectionCount: stats.currentConnectionCount.Load(),
		}
		if snapshot.BytesUp > 0 ||
			snapshot.BytesDown > 0 ||
			snapshot.CurrentConnectionCount > 0 {
			result[region] = snapshot
		} else {
			regionsToDelete = append(regionsToDelete, region)
		}
	}
	for _, region := range regionsToDelete {
		delete(proxy.regionActivity, region)
	}
	return result
}

func (proxy *Proxy) activityUpdate(ctx context.Context) {

	activityUpdatePeriod := proxyActivityUpdatePeriod
	ticker := time.NewTicker(activityUpdatePeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			bytesUp := proxy.activityBytesUp.Swap(0)
			bytesDown := proxy.activityBytesDown.Swap(0)
			regionActivity := proxy.snapshotAndResetRegionActivity()
			proxy.eventReceiver.Activity(&ActivityStats{
				ProxyID:                proxy.ID,
				ProxyProviderID:        proxy.config.ProviderID,
				BytesUp:                bytesUp,
				BytesDown:              bytesDown,
				BytesDuration:          activityUpdatePeriod,
				CurrentConnectionCount: proxy.currentConnectionCount.Load(),
				RegionActivity:         regionActivity,
			})
		case <-ctx.Done():
			return
		}
	}
}

func (proxy *Proxy) acquireProxyLimit() (common.ProxyLimitReleaseFunc, error) {

	var release common.ProxyLimitReleaseFunc
	var ok bool

	switch proxy.proxyLimitKind {
	case ProxyLimitKindCommon:
		release, ok = proxy.proxyLimits.TryAcquireCommonClient()

	case ProxyLimitKindPersonal:
		release, ok = proxy.proxyLimits.TryAcquirePersonalClient()

	default:
		return nil, errors.TraceNew("invalid ProxyLimitKind")
	}

	if !ok {
		return nil, errors.TraceNew("proxy capacity exceeded")
	}

	return release, nil
}

func (proxy *Proxy) getTrafficRateLimits() (common.RateLimits, bool) {

	var upstreamBytesPerSecond, downstreamBytesPerSecond int
	switch proxy.proxyLimitKind {
	case ProxyLimitKindCommon:
		_, _, _, upstreamBytesPerSecond, downstreamBytesPerSecond =
			proxy.proxyLimits.GetCommonLimits()

	case ProxyLimitKindPersonal:
		_, _, _, upstreamBytesPerSecond, downstreamBytesPerSecond =
			proxy.proxyLimits.GetPersonalLimits()

	default:
		return common.RateLimits{}, false
	}

	if upstreamBytesPerSecond == 0 && downstreamBytesPerSecond == 0 {
		return common.RateLimits{}, false
	}

	// Throttling is applied to the proxy-to-destination connection, where
	// writes flow upstream and reads flow downstream.
	return common.RateLimits{
		ReadBytesPerSecond:  int64(downstreamBytesPerSecond),
		WriteBytesPerSecond: int64(upstreamBytesPerSecond),
	}, true
}

func (proxy *Proxy) applyRateLimit(limitIP string) error {

	if proxy.rateLimitQuantity <= 0 || proxy.rateLimitInterval <= 0 {
		return nil
	}

	proxy.limitsMutex.Lock()
	defer proxy.limitsMutex.Unlock()

	var rateLimiter *rate.Limiter

	entry, ok := proxy.rateLimiters.Get(limitIP)
	if ok {
		rateLimiter = entry.(*rate.Limiter)
	} else {
		limit := float64(proxy.rateLimitQuantity) / proxy.rateLimitInterval.Seconds()
		rateLimiter = rate.NewLimiter(rate.Limit(limit), proxy.rateLimitQuantity)
		proxy.rateLimiters.Set(limitIP, rateLimiter, proxy.rateLimitInterval)
	}

	if !rateLimiter.Allow() {
		return errors.Trace(std_errors.New("rate limit exceeded"))
	}

	return nil
}

func (proxy *Proxy) takePerIPMaxConcurrent(limitIP string) error {

	proxy.limitsMutex.Lock()
	defer proxy.limitsMutex.Unlock()

	count := proxy.perIPConcurrentConnections[limitIP]
	if proxy.perIPMaxConcurrent > 0 && count >= proxy.perIPMaxConcurrent {
		return errors.TraceNew("max per IP concurrent exceeded")
	}
	proxy.perIPConcurrentConnections[limitIP] = count + 1

	return nil
}

func (proxy *Proxy) replacePerIPMaxConcurrent(limitIP string) {

	proxy.limitsMutex.Lock()
	defer proxy.limitsMutex.Unlock()

	count := proxy.perIPConcurrentConnections[limitIP] - 1
	if count <= 0 {
		delete(proxy.perIPConcurrentConnections, limitIP)
	} else {
		proxy.perIPConcurrentConnections[limitIP] = count
	}
}

func (proxy *Proxy) resolve(
	ctx context.Context,
	destinationAddress string) (netTCPAddrs, bool, error) {

	var addrs netTCPAddrs
	cached := false

	host, portStr, err := net.SplitHostPort(destinationAddress)
	if err != nil {
		return addrs, false, errors.Trace(err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return addrs, false, errors.Trace(err)
	}

	IP := net.ParseIP(host)
	if IP != nil {

		if !proxy.config.AllowBogons && common.IsBogon(IP) {
			return addrs, false, errors.TraceNew("IP is bogon")
		}

		return netIPAddrs(IP, port), false, nil
	}

	if proxy.dnsCache != nil {

		// The cache key includes the port since the cached values are full
		// TCP dial addresses, including port, partitioned and ready for
		// netDialParallel. This does mean the same host with a different
		// port will be a cache miss, but the much more common case is same
		// host and port.
		//
		// Cached values may be read by concurrent goroutines and
		// must not be mutated.

		cachedAddrs, ok := proxy.dnsCache.Get(destinationAddress)
		if ok {
			addrs = cachedAddrs.(netTCPAddrs)
			cached = true
		}
	}

	if addrs.isEmpty() {

		ipAddrs, err := proxy.dnsResolver.LookupIPAddr(ctx, host)
		if err != nil {
			err = common.RedactNetError(err)
			return addrs, false, errors.Trace(err)
		}

		// Perform the bogon check here so it doesn't need to be repeated for
		// cached values.

		for _, ipAddr := range ipAddrs {
			if !proxy.config.AllowBogons && common.IsBogon(ipAddr.IP) {
				return addrs, false, errors.TraceNew("IP is bogon")
			}
		}

		addrs = netPartitionAddrs(ipAddrs, port)

		if proxy.dnsCache != nil && !addrs.isEmpty() {
			proxy.dnsCache.Add(
				destinationAddress,
				addrs,
				lrucache.DefaultExpiration)
		}
	}

	return addrs, cached, nil
}

func makeBindToDeviceControl(interfaceName string) func(string, string, syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var controlErr error
		err := c.Control(func(fd uintptr) {
			err := tun.BindToDevice(int(fd), interfaceName)
			if err != nil {
				controlErr = errors.Tracef("BindToDevice failed: %v", err)
				return
			}
		})
		if controlErr != nil {
			return errors.Trace(controlErr)
		}
		if err != nil {
			return errors.Trace(err)
		}
		return nil
	}
}

// redactingProxyEventReceiver is a ProxyEventReceiver which redacts IP addresses from
// log messages and ConnectionStats.Failure errors.
type redactingProxyEventReceiver struct {
	ProxyEventReceiver
}

func newRedactingProxyEventReceiver(
	eventReceiver ProxyEventReceiver) *redactingProxyEventReceiver {

	return &redactingProxyEventReceiver{ProxyEventReceiver: eventReceiver}
}

func (r *redactingProxyEventReceiver) Connection(stats *ConnectionStats) {
	stats.Failure = common.RedactIPAddressesString(stats.Failure)
	r.ProxyEventReceiver.Connection(stats)
}

func (r *redactingProxyEventReceiver) DebugLog(proxyID string, message string) {
	r.ProxyEventReceiver.DebugLog(proxyID, common.RedactIPAddressesString(message))
}

func (r *redactingProxyEventReceiver) InfoLog(proxyID string, message string) {
	r.ProxyEventReceiver.InfoLog(proxyID, common.RedactIPAddressesString(message))
}

func (r *redactingProxyEventReceiver) WarningLog(proxyID string, message string) {
	r.ProxyEventReceiver.WarningLog(proxyID, common.RedactIPAddressesString(message))
}

func (r *redactingProxyEventReceiver) ErrorLog(proxyID string, message string) {
	r.ProxyEventReceiver.ErrorLog(proxyID, common.RedactIPAddressesString(message))
}
