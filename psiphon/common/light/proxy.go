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
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
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
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/obfuscator"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/proxyheader"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/quic"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tlsdialer"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tun"
	lrucache "github.com/cognusion/go-cache-lru"
	"golang.org/x/time/rate"
)

const (
	LIGHT_PROTOCOL_TLS  = "TLS"
	LIGHT_PROTOCOL_QUIC = "QUIC"

	obfuscationKeySize              = 32
	defaultPreHeaderDeadlineMin     = 30 * time.Second
	defaultPreHeaderDeadlineMax     = 120 * time.Second
	preHeaderDeadlineStep           = 10 * time.Second
	defaultInactivityTimeout        = 5 * time.Minute // Matches server.SSH_CONNECTION_READ_DEADLINE, the longer, post API handshake server inactivity timeout.
	defaultUpstreamDialTimeout      = 5 * time.Second
	defaultRelayBufferSize          = 16384
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

	defaultTunnelUpstreamDialTimeout = 10 * time.Second
)

// ProxyTLSDialer is a callback that establishes the proxy-to-server TCP and
// TLS connection. The dialer allows for integrating Psiphon features including
// utls, passthrough, public-key pin verification, session caching, and replay.
//
// The returned exporter binds the proxy report to the TLS connection.
//
// The dialer closes its connections on error. completedTCP and completedTLS
// record establishment even if a later step fails.
//
// The specified tlsProfile must be a utls TLS 1.3 ClientHello parrot
// fingerprint, or a randomized fingerprint that produces a TLS 1.3
// ClientHello with the given randomizedTLSProfileSeed.
type ProxyTLSDialer func(
	ctx context.Context,
	address string,
	tlsProfile string,
	randomizedTLSProfileSeed *prng.Seed,
	sni string,
	fragmentClientHello bool,
	tlsPadding int,
	passthroughMessage []byte,
	verifyPin string) (
	conn net.Conn,
	exporter []byte,
	completedTCP time.Time,
	completedTLS time.Time,
	err error)

// ProxyQUICDialer is a callback that establishes the proxy-to-server QUIC
// connection. The dialer allows for integrating Psiphon obfuscation features.
//
// The returned exporter binds the proxy report to the QUIC connection.
//
// The dialer closes its connections on error. completedQUIC records QUIC
// establishment even if a later step fails.
type ProxyQUICDialer func(
	ctx context.Context,
	address string,
	sni string,
	quicVersion string,
	clientHelloSeed *prng.Seed,
	obfuscatedQUICPaddingSeed *prng.Seed,
	obfuscationKey string,
	verifyPin string) (
	conn net.Conn,
	exporter []byte,
	completedQUIC time.Time,
	err error)

// ProxyConfig specifies the configuration of a light proxy.
// Unless noted otherwise, fields apply in both fallback and tunnel modes.
// The Proxy retains and reads the config, which must not be modified while
// Run is active.
//
// When ProxyLimits is specified, connections use the shared common or personal
// limits according to the authenticated personal compartment ID.
//
// When ProxyLimits is nil, ProxyConfig limit parameters provide common-only
// limits for compatibility with standalone fallback proxies.
type ProxyConfig struct {
	// ProxyID is required in fallback mode and must be empty in tunnel mode.
	// Tunnel mode derives the ID from TunnelProxyPrivateKey.
	ProxyID string `json:",omitempty"`

	// ProviderID identifies the proxy provider in emitted statistics.
	ProviderID string `json:",omitempty"`

	// DialAddresses specifies public endpoints paired with ListenAddresses.
	// In tunnel mode it may be omitted when ListenAddresses is provided;
	// proxy GeoIP is then unavailable. Distributed entries still need addresses.
	DialAddresses []ProxyAddress `json:",omitempty"`

	// ListenAddresses specifies local endpoints paired by index with
	// DialAddresses. When omitted, DialAddresses is used.
	ListenAddresses []ProxyAddress `json:",omitempty"`

	// ObfuscationKey is the hex key for authenticating ingress TLS
	// passthrough messages and QUIC handshakes, and for QUIC obfuscation.
	ObfuscationKey string `json:",omitempty"`

	// TLSCertificate is the PEM-encoded certificate shared by ingress TLS
	// and QUIC listeners.
	TLSCertificate []byte `json:",omitempty"`

	// TLSPrivateKey is the PEM-encoded private key for TLSCertificate.
	TLSPrivateKey []byte `json:",omitempty"`

	// PassthroughAddress receives unauthenticated ingress TLS connections.
	// Required for TLS ingress in both modes; ignored for QUIC ingress.
	PassthroughAddress string `json:",omitempty"`

	// AllowedDestinations restricts client-selected upstream destinations in
	// fallback mode only. Tunnel mode uses signed dial authorizations.
	AllowedDestinations []string `json:",omitempty"`

	// PreHeaderDeadlineMin is the lower bound for the timeout to receive the
	// light proxy header. Defaults to "30s".
	PreHeaderDeadlineMin string `json:",omitempty"`

	// PreHeaderDeadlineMax is the upper bound for the timeout to receive the
	// light proxy header. Defaults to "120s".
	PreHeaderDeadlineMax string `json:",omitempty"`

	// InactivityTimeout limits time without a read from the client after
	// accepting the light proxy header. Defaults to "5m"; "0s" disables it.
	InactivityTimeout string `json:",omitempty"`

	// UpstreamDialTimeout limits upstream resolution, dialing, transport
	// handshakes, and tunnel proxy report transmission.
	// Defaults to 10s in tunnel mode and 5s otherwise.
	UpstreamDialTimeout string `json:",omitempty"`

	// RelayBufferSize specifies each relay copy buffer size in bytes.
	RelayBufferSize int `json:",omitempty"`

	// PerIPRateLimitQuantity sets the connection rate per PerIPRateLimitInterval
	// and the burst size, per IPv4 address or IPv6 /56.
	PerIPRateLimitQuantity *int `json:",omitempty"`

	// PerIPRateLimitInterval specifies the interval for PerIPRateLimitQuantity.
	// Both fields must be set together.
	PerIPRateLimitInterval string `json:",omitempty"`

	// PerIPMaxConcurrent limits concurrent connections per IPv4 address or
	// IPv6 /56, shared by common and personal clients.
	PerIPMaxConcurrent *int `json:",omitempty"`

	// MaxConcurrent limits concurrent common clients when ProxyLimits is nil.
	MaxConcurrent *int `json:",omitempty"`

	// LimitUpstreamBytesPerSecond limits each common client's upstream rate.
	// Used only when ProxyLimits is nil.
	LimitUpstreamBytesPerSecond int `json:",omitempty"`

	// LimitDownstreamBytesPerSecond limits each common client's downstream rate.
	// Used only when ProxyLimits is nil.
	LimitDownstreamBytesPerSecond int `json:",omitempty"`

	// DialFallbackDelay gives the first IP address family a head start when
	// dialing a fallback destination. Defaults to "300ms".
	DialFallbackDelay string `json:",omitempty"`

	// DNSResolverCacheMaxSize limits cached fallback destination resolutions.
	// Tunnel destinations are literal IPs; passthrough lookups are not cached.
	DNSResolverCacheMaxSize *int `json:",omitempty"`

	// DNSResolverCacheTTL specifies the fallback destination resolution cache TTL.
	DNSResolverCacheTTL string `json:",omitempty"`

	// SplitUpstreamInterfaceName binds non-tunnel TCP, DNS, and non-loopback
	// TLS passthrough traffic to an interface. SplitUpstreamInterfaceName
	// cannot be set in tunnel mode, where ProxyTLSDialer, ProxyQUICDialer,
	// and TLSPassthroughDialer bypass it and are responsible for binding
	// their own sockets.
	SplitUpstreamInterfaceName string `json:",omitempty"`

	// SplitDownstreamInterfaceName binds ingress traffic to an interface.
	SplitDownstreamInterfaceName string `json:",omitempty"`

	// ProxyProtocolHeaderMACKeys maps sponsor IDs to encoded MAC keys.
	// Fallback mode only.
	ProxyProtocolHeaderMACKeys map[string]string `json:",omitempty"`

	// ProxyProtocolHeaderCustomTLVs maps sponsor IDs to encoded custom TLVs.
	// Fallback mode only.
	ProxyProtocolHeaderCustomTLVs map[string]string `json:",omitempty"`

	// ProxyProtocolHeaderTargetDestinationAddresses maps sponsor IDs to
	// hosts (domain or IP, without a port) that receive PROXY protocol headers
	// on any port. Match the requested host, not a resolved IP. Fallback mode only.
	ProxyProtocolHeaderTargetDestinationAddresses map[string][]string `json:",omitempty"`

	// ProxyLimits provides shared, dynamic proxy limits in both modes.
	// Required when PersonalCompartmentID is set.
	ProxyLimits *common.ProxyLimits `json:"-"`

	// GetCurrentNetworkContext optionally supplies a context cancelled when the
	// active network changes, to interrupt Light client connections.
	GetCurrentNetworkContext func() context.Context `json:"-"`

	// LogDestinationAddresses includes upstream addresses in statistics.
	LogDestinationAddresses bool `json:",omitempty"`

	// AllowBogons permits upstream connections to bogon addresses and the
	// proxy's configured public IPs in both fallback and tunnel modes.
	AllowBogons bool `json:",omitempty"`

	// EmitActivity enables periodic activity callbacks.
	EmitActivity bool `json:",omitempty"`

	// EnableDebugLogs enables per-connection debug logs.
	EnableDebugLogs bool `json:",omitempty"`

	// TunnelMode enables the proxy-to-server TLS or QUIC tunnel path.
	TunnelMode bool `json:"-"`

	// TunnelDialAuthorizationPublicKey verifies destination authorizations.
	// Tunnel mode only.
	TunnelDialAuthorizationPublicKey ed25519.PublicKey `json:"-"`

	// TunnelProxyPrivateKey signs reports and determines the proxy ID.
	// Tunnel mode only.
	TunnelProxyPrivateKey inproxy.SessionPrivateKey `json:"-"`

	// TunnelTrustedProxyAuthorization optionally authorizes this proxy to
	// report trusted original client IPs. Tunnel mode only.
	TunnelTrustedProxyAuthorization []byte `json:"-"`

	// TunnelProxyReportPaddingMinBytes sets minimum report padding; default 0.
	// Tunnel mode only.
	TunnelProxyReportPaddingMinBytes *int `json:"-"`

	// TunnelProxyReportPaddingMaxBytes sets maximum report padding; default 1024.
	// Tunnel mode only.
	TunnelProxyReportPaddingMaxBytes *int `json:"-"`

	// ProxyPlatform identifies the proxy platform in tunnel reports.
	// Tunnel mode only.
	ProxyPlatform string `json:"-"`

	// ProxyVersion identifies the proxy version in tunnel reports.
	// Tunnel mode only.
	ProxyVersion int64 `json:"-"`

	// ProxyBuildRev identifies the proxy build revision in tunnel reports.
	// Tunnel mode only.
	ProxyBuildRev []byte `json:"-"`

	// ProxyTLSDialer establishes the proxy-to-server TLS connection.
	// Tunnel mode only.
	ProxyTLSDialer ProxyTLSDialer `json:"-"`

	// ProxyQUICDialer establishes the proxy-to-server QUIC connection.
	// Tunnel mode only.
	ProxyQUICDialer ProxyQUICDialer `json:"-"`

	// TLSPassthroughDialer dials non-loopback TLS passthrough connections,
	// allowing the host to apply its own device binding and DNS resolution.
	// Tunnel mode only, where it is required.
	TLSPassthroughDialer func(network, address string) (net.Conn, error) `json:"-"`

	// PersonalCompartmentID is the unpadded base64 personal pairing secret.
	// Used in both modes; requires ProxyLimits.
	PersonalCompartmentID string `json:",omitempty"`
}

// ConnectionStats are the proxy connection stats reported to
// ProxyEventReceiver at the end of a connection. If the connection failed to
// fully establish, Failure reports the reason. Values that the client sends
// in the light header will be zero values when the light header was not read
// successfully, and the proxy's phase-completed timestamps will be zero
// values when the phase was not completed.
//
// Byte counts may exclude final TLS close-notify traffic.
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
	Protocol                    string
	TLSProfile                  string
	QUICVersion                 string
	SNI                         string
	TLSClientHelloFragmented    bool
	TLSClientHelloPadding       int
	TLSDidResume                bool
	ClientTCPDuration           time.Duration
	ClientTLSDuration           time.Duration
	ClientQUICDuration          time.Duration
	ProxyCompletedTCP           time.Time
	ProxyCompletedTLS           time.Time
	ProxyCompletedQUIC          time.Time
	ProxyCompletedLightHeader   time.Time
	ProxyCompletedUpstreamDNS   time.Time
	ProxyCompletedUpstreamTCP   time.Time
	ProxyCompletedUpstreamTLS   time.Time
	ProxyCompletedUpstreamQUIC  time.Time
	UpstreamDNSCached           bool
	ProxyProtocolHeaderAdded    bool
	ProxyProtocolHeaderReplaced bool
	BytesRead                   int64
	BytesWritten                int64
	Failure                     string

	MatchedPersonalCompartments bool
}

// ActivityStats are proxy activity stats reported to ProxyEventReceiver.
type ActivityStats struct {
	ProxyID                string
	ProxyProviderID        string
	BytesUp                int64
	BytesDown              int64
	BytesDuration          time.Duration
	CurrentConnectionCount int64
	PersonalRegionActivity map[string]RegionActivitySnapshot
	CommonRegionActivity   map[string]RegionActivitySnapshot
}

// RegionActivitySnapshot holds personal or common activity for one client region.
type RegionActivitySnapshot struct {
	BytesUp           int64 `json:"bytesUp"`
	BytesDown         int64 `json:"bytesDown"`
	ConnectingClients int64 `json:"connectingClients"`
	ConnectedClients  int64 `json:"connectedClients"`
}

// ProxyEventReceiver receives event callbacks from a light proxy, and handles
// logging and stats shipping. ProxyEventReceiver callbacks should not block
// on processing and instead should dispatch any work that is to be performed.
type ProxyEventReceiver interface {
	Listening(address, ingressProtocol string)

	// Started is called once per Run, after all listeners bind and their
	// Listening callbacks complete. It is not called if setup fails.
	Started()

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

	// Activity is called serially, with a final update before Run returns.
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
//
// Proxy does not limit TCP handshakes, pre-header connections or irregular
// connection events from unauthenticated peers. Deployments should use
// host-based ingress rate and connection limits, such as Psiphon server's
// configureIptablesAcceptRateLimitChain.
type Proxy struct {
	config                           *ProxyConfig
	lookupGeoIP                      LookupGeoIP
	eventReceiver                    ProxyEventReceiver
	ID                               string
	proxyGeoIPData                   []common.GeoIPData
	proxyIPs                         []net.IP
	tlsConfig                        *tls.Config
	listenAddresses                  []ProxyAddress
	obfuscatorSeedHistory            *obfuscator.SeedHistory
	allowedDestinations              common.StringLookup
	proxyProtocolHeaderConfigs       map[string]proxyProtocolHeaderConfig
	preHeaderDeadline                time.Duration
	inactivityTimeout                time.Duration
	upstreamDialTimeout              time.Duration
	relayBufferSize                  int
	relayBufferPool                  sync.Pool
	rateLimitQuantity                int
	rateLimitInterval                time.Duration
	perIPMaxConcurrent               int
	dialFallbackDelay                time.Duration
	tunnelDialAuthorizationPublicKey ed25519.PublicKey
	tunnelTrustedProxyAuthorization  []byte
	tunnelProxyReportPaddingMinBytes int
	tunnelProxyReportPaddingMaxBytes int
	tunnelProxyPlatform              uint8
	tunnelProxyBuildRev              []byte
	personalCompartmentID            []byte

	listenConfig *net.ListenConfig
	dialer       *net.Dialer

	limitsMutex                sync.Mutex
	perIPConcurrentConnections map[string]int
	rateLimiters               *lrucache.Cache
	proxyLimits                *common.ProxyLimits

	dnsResolver *net.Resolver
	dnsCache    *lrucache.Cache

	connectionNumber atomic.Int64
	paused           atomic.Bool

	lastActivityUpdate     time.Time
	activityBytesUp        atomic.Int64
	activityBytesDown      atomic.Int64
	currentConnectionCount atomic.Int64

	personalStatsMutex     sync.Mutex
	personalRegionActivity map[string]*regionActivity

	commonStatsMutex     sync.Mutex
	commonRegionActivity map[string]*regionActivity
}

type regionActivity struct {
	bytesUp           atomic.Int64
	bytesDown         atomic.Int64
	connectingClients atomic.Int64
	connectedClients  atomic.Int64
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

	listenAddresses, err := ValidateProxyConfigAddresses(
		config.DialAddresses, config.ListenAddresses, !config.TunnelMode)
	if err != nil {
		return nil, errors.Trace(err)
	}
	protocols := getLightProtocols(listenAddresses)
	if common.Contains(protocols, LIGHT_PROTOCOL_QUIC) && !quic.Enabled() {
		return nil, errors.TraceNew("QUIC is not enabled")
	}

	err = validateTunnelProxyConfig(config)
	if err != nil {
		return nil, errors.Trace(err)
	}

	tunnelProxyReportPaddingMinBytes := 0
	if config.TunnelProxyReportPaddingMinBytes != nil {
		tunnelProxyReportPaddingMinBytes = *config.TunnelProxyReportPaddingMinBytes
	}
	tunnelProxyReportPaddingMaxBytes := maxTunnelProxyReportPadding
	if config.TunnelProxyReportPaddingMaxBytes != nil {
		tunnelProxyReportPaddingMaxBytes = *config.TunnelProxyReportPaddingMaxBytes
	}
	if tunnelProxyReportPaddingMinBytes < 0 ||
		tunnelProxyReportPaddingMaxBytes < tunnelProxyReportPaddingMinBytes {

		return nil, errors.TraceNew("invalid proxy report padding range")
	}

	proxyID := config.ProxyID
	if config.TunnelMode {
		proxyID, err = GetTunnelProxyID(config.TunnelProxyPrivateKey)
		if err != nil {
			return nil, errors.Trace(err)
		}
		if config.ProxyID != "" {
			return nil, errors.TraceNew("unexpected proxy ID in tunnel mode")
		}
	} else if proxyID == "" {
		return nil, errors.TraceNew("missing proxy ID")
	}

	if config.ObfuscationKey == "" {
		return nil, errors.TraceNew("missing obfuscation key")
	}

	// The obfuscation key is used as a hex string. Clients generate
	// lowercase hex from the key bytes in the proxy entry, so the proxy must
	// use the same format.
	_, err = hex.DecodeString(config.ObfuscationKey)
	if err != nil {
		return nil, errors.TraceNew("invalid obfuscation key")
	}
	config.ObfuscationKey = strings.ToLower(config.ObfuscationKey)

	var personalCompartmentID []byte
	if config.PersonalCompartmentID != "" {
		id, err := inproxy.IDFromString(config.PersonalCompartmentID)
		if err != nil {
			return nil, errors.TraceNew("invalid personal compartment ID")
		}
		personalCompartmentID = id[:]
		if config.ProxyLimits == nil {
			return nil, errors.TraceNew("personal pairing requires ProxyLimits")
		}
	}

	// In the TLS light proxy protocol, the passthrough message serves as
	// authentication that the client has the proxy entry and knows the
	// obfuscation key, so passthrough must be enabled.
	//
	// Future enhancement: support enabling passthrough mode without an actual
	// upstream passthrough address?

	if common.Contains(protocols, LIGHT_PROTOCOL_TLS) &&
		config.PassthroughAddress == "" {

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
		config.ProxyProtocolHeaderCustomTLVs,
		config.ProxyProtocolHeaderTargetDestinationAddresses)
	if err != nil {
		return nil, errors.Trace(err)
	}

	preHeaderDeadlineMin := defaultPreHeaderDeadlineMin
	if config.PreHeaderDeadlineMin != "" {
		var err error
		preHeaderDeadlineMin, err = time.ParseDuration(config.PreHeaderDeadlineMin)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	preHeaderDeadlineMax := defaultPreHeaderDeadlineMax
	if config.PreHeaderDeadlineMax != "" {
		var err error
		preHeaderDeadlineMax, err = time.ParseDuration(config.PreHeaderDeadlineMax)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	if preHeaderDeadlineMin < 0 || preHeaderDeadlineMax < preHeaderDeadlineMin {
		return nil, errors.TraceNew("invalid pre-header deadline")
	}

	// Vary the pre-header deadline per proxy, using the selected value
	// consistently.
	seed := prng.Seed(sha256.Sum256([]byte(config.ObfuscationKey)))
	deadlinePRNG, err := prng.NewPRNGWithSaltedSeed(&seed, "light-proxy-pre-header-deadline")
	if err != nil {
		return nil, errors.Trace(err)
	}
	steps := int((preHeaderDeadlineMax - preHeaderDeadlineMin) / preHeaderDeadlineStep)
	preHeaderDeadline := preHeaderDeadlineMin +
		time.Duration(deadlinePRNG.Range(0, steps))*preHeaderDeadlineStep

	inactivityTimeout := defaultInactivityTimeout
	if config.InactivityTimeout != "" {
		var err error
		inactivityTimeout, err = time.ParseDuration(config.InactivityTimeout)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	if inactivityTimeout < 0 {
		return nil, errors.TraceNew("invalid inactivity timeout")
	}

	upstreamDialTimeout := defaultUpstreamDialTimeout
	if config.TunnelMode {
		upstreamDialTimeout = defaultTunnelUpstreamDialTimeout
	}
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

	// In tunnel mode, the host's dialers are used for all dials, and the
	// proxy's own dialer and DNS resolver are not initialized.
	var dialer *net.Dialer
	if !config.TunnelMode {
		dialer = &net.Dialer{}
	}

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

		// In tunnel mode, SplitUpstreamInterfaceName is not set, and no
		// upstream interface is selected or bound.
		bindUpstream := dialer != nil

		upstreamInterfaceName := config.SplitUpstreamInterfaceName
		downstreamInterfaceName := config.SplitDownstreamInterfaceName
		if bindUpstream && upstreamInterfaceName == "" {
			upstreamInterfaceName = common.FindInterfaceExcluding(downstreamInterfaceName)
		}
		if downstreamInterfaceName == "" {
			downstreamInterfaceName = common.FindInterfaceExcluding(upstreamInterfaceName)
		}
		if bindUpstream && upstreamInterfaceName == "" {
			return nil, errors.TraceNew(
				"unable to determine upstream interface; set SplitUpstreamInterfaceName")
		}
		if downstreamInterfaceName == "" {
			return nil, errors.TraceNew(
				"unable to determine downstream interface; set SplitDownstreamInterfaceName")
		}

		listenConfig.Control = makeBindToDeviceControl(downstreamInterfaceName)
		if bindUpstream {
			dialer.Control = makeBindToDeviceControl(upstreamInterfaceName)
		}
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

	var dnsResolver *net.Resolver
	var dnsCache *lrucache.Cache
	if dialer != nil {
		dnsResolver = &net.Resolver{
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

		if dnsResolverCacheMaxSize > 0 && dnsResolverCacheTTL > 0 {
			dnsCache = lrucache.NewWithLRU(
				dnsResolverCacheTTL,
				dnsResolverCacheReapFrequency,
				dnsResolverCacheMaxSize)
		}
	}

	proxyGeoIPData := make([]common.GeoIPData, len(listenAddresses))
	proxyIPs := make([]net.IP, len(config.DialAddresses))
	for i, address := range config.DialAddresses {
		proxyGeoIPData[i] = lookupGeoIP(address.IPAddress)
		proxyIPs[i] = net.ParseIP(address.IPAddress)
	}

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

	proxyLimits := config.ProxyLimits
	if proxyLimits == nil {
		proxyLimits, err = newProxyLimitsFromConfig(config, maxConcurrent)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	proxy := &Proxy{
		config:                     config,
		lookupGeoIP:                lookupGeoIP,
		eventReceiver:              newRedactingProxyEventReceiver(eventReceiver),
		ID:                         proxyID,
		proxyGeoIPData:             proxyGeoIPData,
		proxyIPs:                   proxyIPs,
		tlsConfig:                  tlsConfig,
		listenAddresses:            listenAddresses,
		obfuscatorSeedHistory:      obfuscator.NewSeedHistory(nil),
		allowedDestinations:        common.NewStringLookup(normalizedAllowedDestinations),
		proxyProtocolHeaderConfigs: proxyProtocolHeaderConfigs,
		preHeaderDeadline:          preHeaderDeadline,
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
		dnsResolver:        dnsResolver,
		dnsCache:           dnsCache,
		listenConfig:       listenConfig,
		dialer:             dialer,
		dialFallbackDelay:  dialFallbackDelay,
		tunnelDialAuthorizationPublicKey: append(
			ed25519.PublicKey(nil),
			config.TunnelDialAuthorizationPublicKey...),
		tunnelTrustedProxyAuthorization: append(
			[]byte(nil), config.TunnelTrustedProxyAuthorization...),
		tunnelProxyReportPaddingMinBytes: tunnelProxyReportPaddingMinBytes,
		tunnelProxyReportPaddingMaxBytes: tunnelProxyReportPaddingMaxBytes,
		tunnelProxyPlatform: encodeClientPlatform(
			config.ProxyPlatform),
		tunnelProxyBuildRev:   append([]byte(nil), config.ProxyBuildRev...),
		personalCompartmentID: personalCompartmentID,

		perIPConcurrentConnections: make(map[string]int),
		rateLimiters: lrucache.NewWithLRU(
			0,
			rateLimiterReapHistoryFrequency,
			rateLimiterMaxCacheEntries),
		personalRegionActivity: make(map[string]*regionActivity),
		commonRegionActivity:   make(map[string]*regionActivity),
	}

	if common.Contains(protocols, LIGHT_PROTOCOL_TLS) {
		tlsConfig.PassthroughAddress = config.PassthroughAddress
		if isLoopbackAddress(config.PassthroughAddress) {
			// A split-mode dialer is bound to the upstream interface and cannot
			// reach a loopback passthrough service on the proxy host.
			// TODO: If passthrough targets become user-configurable, consider a
			// SplitPassthroughInterfaceName and dedicated dialer for independently
			// routing passthrough through the upstream, downstream, or default route.
			tlsConfig.PassthroughDialer = net.Dial
		} else if config.TLSPassthroughDialer != nil {
			tlsConfig.PassthroughDialer = config.TLSPassthroughDialer
		} else {
			tlsConfig.PassthroughDialer = proxy.dialer.Dial
		}

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
	}

	return proxy, nil
}

func validateTunnelProxyConfig(config *ProxyConfig) error {
	if !config.TunnelMode {
		if len(config.TunnelDialAuthorizationPublicKey) != 0 ||
			!config.TunnelProxyPrivateKey.IsZero() ||
			len(config.TunnelTrustedProxyAuthorization) != 0 ||
			config.TunnelProxyReportPaddingMinBytes != nil ||
			config.TunnelProxyReportPaddingMaxBytes != nil ||
			config.ProxyPlatform != "" ||
			config.ProxyVersion != 0 ||
			len(config.ProxyBuildRev) != 0 ||
			config.ProxyTLSDialer != nil ||
			config.ProxyQUICDialer != nil ||
			config.TLSPassthroughDialer != nil {

			return errors.TraceNew("unexpected tunnel proxy configuration")
		}
		return nil
	}

	if len(config.ProxyProtocolHeaderMACKeys) != 0 ||
		len(config.ProxyProtocolHeaderCustomTLVs) != 0 ||
		len(config.ProxyProtocolHeaderTargetDestinationAddresses) != 0 {

		return errors.TraceNew("PROXY protocol headers are unsupported in tunnel mode")
	}

	if len(config.TunnelDialAuthorizationPublicKey) !=
		ed25519.PublicKeySize {

		return errors.TraceNew(
			"invalid tunnel dial authorization public key")
	}
	if config.TunnelProxyPrivateKey.IsZero() {
		return errors.TraceNew("missing tunnel proxy private key")
	}
	if config.ProxyTLSDialer == nil && config.ProxyQUICDialer == nil {
		return errors.TraceNew("missing proxy tunnel dialer")
	}
	if config.TLSPassthroughDialer == nil {
		return errors.TraceNew("missing TLS passthrough dialer")
	}
	// ProxyTLSDialer, ProxyQUICDialer, and TLSPassthroughDialer bypass
	// SplitUpstreamInterfaceName.
	if config.SplitUpstreamInterfaceName != "" {
		return errors.TraceNew(
			"SplitUpstreamInterfaceName is unsupported in tunnel mode")
	}
	if config.ProxyVersion < 0 {
		return errors.TraceNew("invalid proxy version")
	}
	if len(config.ProxyBuildRev) > maxTunnelProxyBuildRev {
		return errors.TraceNew("invalid proxy build revision")
	}
	if len(config.TunnelTrustedProxyAuthorization) >
		TunnelTrustedProxyAuthorizationMaxSize {

		return errors.TraceNew("invalid trusted proxy authorization")
	}

	return nil
}

func isLoopbackAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	IP := net.ParseIP(host)
	return IP != nil && IP.IsLoopback()
}

// newProxyLimitsFromConfig initializes common client limits from config.
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
// value is used. Active connections are not closed but are rethrottled.
// Requires ProxyLimits to be nil.
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

	type listener struct {
		net.Listener
		addressIndex int
	}

	listeners := make(
		[]listener,
		0,
		len(proxy.listenAddresses))
	closeListeners := func() {
		for _, listener := range listeners {
			listener.Close()
		}
	}

	for i, address := range proxy.listenAddresses {
		network := "tcp"
		if address.Protocol == LIGHT_PROTOCOL_QUIC {
			network = "udp"
		}

		// Bind each tuple to its stated IP address family.
		if net.ParseIP(address.IPAddress).To4() != nil {
			network += "4"
		} else {
			network += "6"
		}

		var netListener net.Listener
		var err error
		switch address.Protocol {
		case LIGHT_PROTOCOL_TLS:
			// Future enhancement: use psiphon/server.newTCPListenerWithBPF.
			netListener, err = proxy.listenConfig.Listen(
				ctx, network, address.String())

		case LIGHT_PROTOCOL_QUIC:
			var packetConn net.PacketConn
			packetConn, err = proxy.listenConfig.ListenPacket(
				ctx, network, address.String())
			if err == nil {
				netListener, err = quic.Listen(
					nil,
					func(
						peerAddress string,
						err error,
						_ common.LogFields) {

						// Limitation: as in psiphond, this callback, including the
						// GeoIP lookup, runs inline on the QUIC listener's new
						// connection goroutine. See Proxy.

						// Remove QUIC's error trace for consistency with TLS, which reports
						// irregularities without a trace.
						for inner := std_errors.Unwrap(err); inner != nil; inner = std_errors.Unwrap(err) {
							err = inner
						}
						proxy.eventReceiver.IrregularConnection(
							proxy.ID,
							proxy.lookupGeoIP(peerAddress),
							err.Error())
					},
					"",
					packetConn,
					false,
					0,
					proxy.config.ObfuscationKey,
					proxy.obfuscatorSeedHistory,
					&proxy.tlsConfig.Certificates[0],
					false,
					false)
			}
		}
		if err != nil {
			closeListeners()
			return errors.Trace(err)
		}
		listeners = append(
			listeners,
			listener{Listener: netListener, addressIndex: i})
	}

	for _, listener := range listeners {
		proxy.eventReceiver.Listening(
			listener.Addr().String(),
			proxy.listenAddresses[listener.addressIndex].Protocol)
	}

	proxy.eventReceiver.Started()

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	listenerErrors := make(chan error, len(listeners))

	waitGroup := new(sync.WaitGroup)

	// Connection handlers are tracked separately. On stop, the handlers,
	// which close their connections, are awaited before the listeners are
	// closed. Closing a QUIC listener closes its UDP socket, after which
	// QUIC clients would not receive a connection close and would instead
	// wait for an idle timeout. Once stopping, any newly accepted connection
	// is immediately closed.
	var handlersMutex sync.Mutex
	handlersStopping := false
	handlersWaitGroup := new(sync.WaitGroup)

	if proxy.config.EmitActivity {
		proxy.lastActivityUpdate = time.Now()
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			proxy.activityUpdate(runCtx)
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
					if runCtx.Err() != nil {
						break
					}
					// Stop running on any non-temporary Accept error.
					var netErr net.Error
					if std_errors.As(err, &netErr) && netErr.Temporary() {
						proxy.eventReceiver.WarningLog(
							proxy.ID, errors.Trace(err).Error())
						continue
					}
					listenerErrors <- errors.Trace(err)
					cancelRun()
					break
				}
				if proxy.paused.Load() {

					// Limitation: QUIC Accept returns after its handshake, so a
					// paused proxy performs that handshake before rejecting.

					// Immediately close the accepted connection when paused.
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

				handlersMutex.Lock()
				if handlersStopping {
					handlersMutex.Unlock()
					conn.Close()
					continue
				}
				handlersWaitGroup.Add(1)
				handlersMutex.Unlock()

				// Limitation: network changes do not interrupt detached TLS passthrough
				// relays or QUIC connections not yet returned by Accept.
				connCtx := runCtx
				var cancel context.CancelFunc
				if proxy.config.GetCurrentNetworkContext != nil {
					connCtx, cancel = common.MergeContextCancel(
						runCtx, proxy.config.GetCurrentNetworkContext())
				}
				go func(conn net.Conn) {
					defer handlersWaitGroup.Done()
					if cancel != nil {
						defer cancel()
					}
					proxy.eventReceiver.Accepted()
					err := proxy.handleConn(
						connCtx, conn, listener.addressIndex)
					if err != nil && connCtx.Err() == nil {
						proxy.eventReceiver.WarningLog(
							proxy.ID, errors.Trace(err).Error())
					}
				}(conn)
			}
		}()
	}

	<-runCtx.Done()

	handlersMutex.Lock()
	handlersStopping = true
	handlersMutex.Unlock()
	handlersWaitGroup.Wait()

	closeListeners()
	waitGroup.Wait()

	if proxy.config.EmitActivity {
		// Flush bytes after the connection handlers and activity worker stop.
		proxy.emitActivity()
	}

	select {
	case err := <-listenerErrors:
		return errors.Trace(err)
	default:
		return nil
	}
}

func (proxy *Proxy) handleConn(
	ctx context.Context,
	conn net.Conn,
	addressIndex int) (retErr error) {

	var activity *regionActivity
	connected := false
	counted := false
	connToClose := conn
	defer func() {
		connToClose.Close()
		// Limitation: a concurrent TLS Close may count final bytes after this
		// decrement, so those bytes may be omitted if the region bucket is pruned.
		if activity != nil {
			if connected {
				activity.connectedClients.Add(-1)
			} else {
				activity.connectingClients.Add(-1)
			}
		}
		if counted {
			proxy.currentConnectionCount.Add(-1)
		}
	}()

	ingressProtocol := proxy.listenAddresses[addressIndex].Protocol

	var geoIPData common.GeoIPData
	var completedTCP time.Time
	var completedTLS time.Time
	var completedQUIC time.Time
	var clientSNI string
	var tlsClientHelloFragmented bool
	var tlsClientHelloPadding int
	var ingressDidResume bool
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
	var completedUpstreamTLS time.Time
	var completedUpstreamQUIC time.Time
	var upstreamDNSCached bool
	var proxyProtocolHeaderAdded bool
	var proxyProtocolHeaderReplaced bool
	var isPersonal bool

	connectionNum := proxy.connectionNumber.Add(1)

	switch ingressProtocol {
	case LIGHT_PROTOCOL_TLS:
		completedTCP = time.Now().UTC()
	case LIGHT_PROTOCOL_QUIC:
		// Limitation: Light byte and activity metrics exclude QUIC handshake
		// traffic and packet overhead.
		completedQUIC = time.Now().UTC()
	default:
		return errors.TraceNew("unsupported proxy protocol")
	}

	// Connection stats are emitted on connection end, including for any
	// failures after this point.
	defer func() {

		var clientPlatform, clientBuildRev string
		var deviceRegion, sessionID, networkType, tlsProfile, quicVersion string
		var proxyEntryTracker, clientConnectionNum int64
		var clientTCPDuration, clientTLSDuration, clientQUICDuration time.Duration

		if header != nil {
			clientPlatform = decodeClientPlatform(header.ClientPlatform)
			clientBuildRev = hex.EncodeToString(header.ClientBuildRev)
			deviceRegion = header.DeviceRegion
			sessionID = hex.EncodeToString(header.SessionID)
			proxyEntryTracker = header.ProxyEntryTracker
			networkType = decodeNetworkType(header.NetworkType)
			clientConnectionNum = header.ConnectionNum
			tlsProfile = decodeTLSProfile(header.TLSProfile)
			quicVersion = decodeQUICVersion(header.QUICVersion)
			clientTCPDuration = time.Duration(header.TCPDuration)
			clientTLSDuration = time.Duration(header.TLSDuration)
			clientQUICDuration = time.Duration(header.QUICDuration)
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
			ProxyGeoIPData:              proxy.proxyGeoIPData[addressIndex],
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
			Protocol:                    ingressProtocol,
			TLSProfile:                  tlsProfile,
			QUICVersion:                 quicVersion,
			SNI:                         clientSNI,
			TLSClientHelloFragmented:    tlsClientHelloFragmented,
			TLSClientHelloPadding:       tlsClientHelloPadding,
			TLSDidResume:                ingressDidResume,
			ClientTCPDuration:           clientTCPDuration,
			ClientTLSDuration:           clientTLSDuration,
			ClientQUICDuration:          clientQUICDuration,
			ProxyCompletedTCP:           completedTCP,
			ProxyCompletedTLS:           completedTLS,
			ProxyCompletedQUIC:          completedQUIC,
			ProxyCompletedLightHeader:   completedLightHeader,
			ProxyCompletedUpstreamDNS:   completedUpstreamDNS,
			ProxyCompletedUpstreamTCP:   completedUpstreamTCP,
			ProxyCompletedUpstreamTLS:   completedUpstreamTLS,
			ProxyCompletedUpstreamQUIC:  completedUpstreamQUIC,
			UpstreamDNSCached:           upstreamDNSCached,
			ProxyProtocolHeaderAdded:    proxyProtocolHeaderAdded,
			ProxyProtocolHeaderReplaced: proxyProtocolHeaderReplaced,
			BytesRead:                   bytesCounter.bytesRead.Load(),
			BytesWritten:                bytesCounter.bytesWritten.Load(),
			Failure:                     failure,
			MatchedPersonalCompartments: isPersonal,
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
		counted = true
	}

	// Pre-header there is a fixed deadline and no inactivity timeout.

	activityConn, err := common.NewActivityMonitoredConn(
		conn,
		0,
		false,
		nil,
		bytesCounter)
	if err != nil {
		return errors.Trace(err)
	}

	handleCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	unassociateAfter := context.AfterFunc(handleCtx, func() {
		activityConn.Close()
	})
	defer unassociateAfter()

	var preHeaderDeadlineTimer *time.Timer
	if proxy.preHeaderDeadline > 0 {
		if ingressProtocol == LIGHT_PROTOCOL_QUIC {
			// Use a timer for the header timeout since setting a QUIC deadline can
			// block while waiting for the client to open a stream.
			preHeaderDeadlineTimer = time.AfterFunc(
				proxy.preHeaderDeadline,
				func() { activityConn.Close() })
			defer preHeaderDeadlineTimer.Stop()
		} else {
			// Assumes ActivityMonitoredConn doesn't modify the deadline, which
			// it doesn't with inactivityTimeout set to 0.
			err := activityConn.SetDeadline(
				time.Now().Add(proxy.preHeaderDeadline))
			if err != nil {
				return errors.Trace(err)
			}
		}
	}

	var lightConn *lightConn
	switch ingressProtocol {
	case LIGHT_PROTOCOL_TLS:
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
		//   support this, psiphon-tls clears the activityConn pre-header deadline
		//   before starting the relay. In addition, passthrough bytes continue to
		//   be counted for the lifetime of the passthrough relay.

		tlsConn := tls.Server(activityConn, proxy.tlsConfig)
		connToClose = tlsConn

		err = tlsConn.Handshake()
		connectionMetrics := tlsConn.ConnectionMetrics()
		tlsClientHelloFragmented = connectionMetrics.ClientHelloFragmented
		tlsClientHelloPadding = connectionMetrics.ClientHelloPaddingLength
		if err != nil {
			return errors.Trace(err)
		}

		// Future enhancement: record SNI for failed TLS handshakes with
		// tlsConfig.GetConfigForClient. Clone proxy.tlsConfig for each connection.

		completedTLS = time.Now().UTC()
		connectionState := tlsConn.ConnectionState()
		clientSNI = connectionState.ServerName
		ingressDidResume = connectionState.DidResume
		lightConn = newLightConn(tlsConn, nil)

	case LIGHT_PROTOCOL_QUIC:
		stateSource, ok := conn.(interface {
			GetTLSConnectionState() (tls.ConnectionState, error)
		})
		if !ok {
			return errors.TraceNew("missing QUIC TLS connection state")
		}
		connectionState, err := stateSource.GetTLSConnectionState()
		if err != nil {
			return errors.Trace(err)
		}
		clientSNI = connectionState.ServerName
		ingressDidResume = connectionState.DidResume
		lightConn = newLightConn(activityConn, nil)
	}

	header, err = lightConn.readHeader()
	if err != nil {
		return errors.Trace(err)
	}

	// Validate dial stats.
	switch ingressProtocol {
	case LIGHT_PROTOCOL_TLS:
		if header.QUICVersion != 0 || header.QUICDuration != 0 {
			return errors.TraceNew("unexpected ingress QUIC parameters")
		}
		if proxy.config.TunnelMode && header.TLSProfile == 0 {
			return errors.TraceNew("missing ingress TLS profile")
		}

	case LIGHT_PROTOCOL_QUIC:
		if header.TLSProfile != 0 ||
			header.TCPDuration != 0 ||
			header.TLSDuration != 0 {

			return errors.TraceNew("unexpected ingress TLS parameters")
		}
		if header.QUICVersion == 0 {
			return errors.TraceNew("missing ingress QUIC version")
		}
	}

	// The sponsor ID is uppercase by convention; the case lost in header
	// binary encoding.
	sponsorID = strings.ToUpper(hex.EncodeToString(header.SponsorID))

	// Common and personal clients share the same listeners. Only personal
	// clients include a personal compartment ID in the light proxy header.
	// An omitted ID selects common limits, even when a personal ID is
	// configured; a nonempty ID must match.
	if len(header.PersonalCompartmentID) > 0 {
		if subtle.ConstantTimeCompare(
			header.PersonalCompartmentID, proxy.personalCompartmentID) != 1 {

			return errors.TraceNew("invalid personal compartment ID")
		}
		isPersonal = true
	}

	if proxy.config.EmitActivity {
		activity = proxy.getOrCreateRegionActivity(geoIPData.Country, isPersonal)
		// Assign before relay or TLS close callbacks can update byte counts
		// concurrently. Pre-header cancellation only closes the raw connection.
		bytesCounter.assignByteCountsToActivity(activity)
	}

	if preHeaderDeadlineTimer != nil {
		preHeaderDeadlineTimer.Stop()
	}
	unassociateAfter()

	completedLightHeader = time.Now().UTC()

	// Replace the pre-header deadline with the inactivity timeout for an
	// authentic client.
	err = activityConn.SetInactivityTimeout(proxy.inactivityTimeout)
	if err != nil {
		return errors.Trace(err)
	}

	// Apply limits after reading the header so that ConnectionStats.Failure
	// will be accompanied by client characteristics such as sponsor ID. A
	// later enforcement also means the client is authenticated as having the
	// obfuscation key, and a prober behind shared NAT can't consume or
	// observe limits.
	//
	// Limitation: per-IP limits are shared by common and personal clients.
	//
	// TCP handshakes and pre-header connections are outside these limits.
	// See Proxy.

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

	releaseProxyLimit, err := proxy.acquireProxyLimit(isPersonal)
	if err != nil {
		return errors.Trace(err)
	}
	defer releaseProxyLimit()

	var upstreamConn net.Conn
	if proxy.config.TunnelMode {
		upstreamConn, normalizedDestinationAddress,
			completedUpstreamTCP, completedUpstreamTLS, completedUpstreamQUIC, err =
			proxy.dialTunnelServer(
				handleCtx,
				header,
				clientIP,
				ingressProtocol,
				clientSNI,
				tlsClientHelloFragmented,
				tlsClientHelloPadding,
				ingressDidResume,
				isPersonal)
		if err != nil {
			err = common.RedactNetError(err)
			return errors.Trace(err)
		}
	} else {
		normalizedDestinationAddress, err =
			normalizeDestinationAddress(header.DestinationAddress)
		if err != nil {
			// The parser error can include the client-supplied destination,
			// even when LogDestinationAddresses is disabled.
			return errors.TraceNew("invalid destination address")
		}
		if proxy.allowedDestinations.Len() > 0 &&
			!proxy.allowedDestinations.Contains(
				normalizedDestinationAddress) {

			return errors.TraceNew("disallowed destination")
		}

		dialCtx, dialCancel := context.WithTimeout(
			ctx, proxy.upstreamDialTimeout)
		defer dialCancel()

		// In addition to resolving domains, proxy.resolve rejects bogons and
		// the proxy's configured IPs, including resolved destinations.
		// Limitation: with NAT64, these checks see only the IPv6 destination;
		// the gateway must restrict destinations after translation.

		upstreamAddrs, cached, err := proxy.resolve(
			dialCtx, normalizedDestinationAddress)
		if err != nil {
			err = common.RedactNetError(err)
			return errors.Trace(err)
		}

		upstreamDNSCached = cached
		completedUpstreamDNS = time.Now().UTC()

		upstreamConn, err = netDialParallel(
			dialCtx,
			proxy.dialFallbackDelay,
			upstreamAddrs,
			proxy.dialer)
		if err != nil {
			err = common.RedactNetError(err)
			return errors.Trace(err)
		}
		dialCancel()

		completedUpstreamTCP = time.Now().UTC()
	}

	// Avoid unbounded upstream stalls. Without a timeout, a blocked upstream
	// write keeps the connection open after the client is gone. activeOnWrite
	// is true since this timeout only needs to detect no progress.
	upstreamActivityConn, err := common.NewActivityMonitoredConn(
		upstreamConn, proxy.inactivityTimeout, true, nil)
	if err != nil {
		upstreamConn.Close()
		return errors.Trace(err)
	}

	throttledConn := common.NewThrottledConn(
		upstreamActivityConn, true, common.RateLimits{})
	defer throttledConn.Close()

	unassociateAfter = context.AfterFunc(handleCtx, func() {
		// Interrupt relay (or PROXY protocol read).
		lightConn.Close()
		throttledConn.Close()
	})
	defer unassociateAfter()

	// The client-reported sponsor ID selects the sponsor MAC key;
	// it does not convey an entitlement.
	proxyProtocolHeaderConfig, addProxyProtocolHeader :=
		proxy.proxyProtocolHeaderConfigs[sponsorID]
	if proxy.config.TunnelMode {
		addProxyProtocolHeader = false
	} else if addProxyProtocolHeader {
		// normalizeDestinationAddress already validated and normalized this host.
		host, _, _ := net.SplitHostPort(normalizedDestinationAddress)
		addProxyProtocolHeader =
			proxyProtocolHeaderConfig.targetDestinationAddresses.Contains(host)
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

		sourceIP := net.ParseIP(clientIP)
		if sourceIP == nil {
			return errors.TraceNew("invalid client IP")
		}

		upstreamTCPAddr, ok := upstreamConn.RemoteAddr().(*net.TCPAddr)
		if !ok {
			return errors.TraceNew("unexpected upstream address type")
		}

		macKey := proxyProtocolHeaderConfig.macKey
		wireHeader, err := proxyheader.MakeProxyProtocolHeader(
			macKey[:proxyheader.ProxyProtocolHeaderKeyIDSize],
			macKey[proxyheader.ProxyProtocolHeaderKeyIDSize:],
			proxyProtocolHeaderConfig.customTLV,
			sourceIP,
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

	// Throttling applies only to the relayed client flow, not TLS handshakes,
	// the light proxy header, proxy report, or PROXY protocol header.
	//
	// Registering the connection applies the current rate limits.

	if isPersonal {
		proxy.proxyLimits.RegisterPersonalConn(throttledConn)
	} else {
		proxy.proxyLimits.RegisterCommonConn(throttledConn)
	}
	defer proxy.proxyLimits.UnregisterConn(throttledConn)

	upstreamConn = throttledConn
	if proxy.config.TunnelMode {
		framingConn := newLightConn(upstreamConn, nil)
		// Limit client-driven padding on the proxy's upstream writes. The
		// server caps its own padding; see NewLightFramingConn. The client's
		// own first-hop padding is self-directed.
		framingConn.maxPaddedWrites = prng.Range(
			maxPaddedWritesMin, maxPaddedWritesMax)
		upstreamConn = framingConn
	}

	if activity != nil {
		// Increment first to avoid a premature prune. A concurrent snapshot may
		// briefly count the client as both connecting and connected; this is
		// accepted to keep updates lock-free.
		activity.connectedClients.Add(1)
		activity.connectingClients.Add(-1)
		connected = true
	}

	copyWithRelayBuffer := func(dst net.Conn, src net.Conn) (int64, error) {
		relayBuffer := proxy.relayBufferPool.Get().(*[]byte)
		defer proxy.relayBufferPool.Put(relayBuffer)
		if proxy.config.TunnelMode {
			n, err := RelayLightFrames(dst, src, *relayBuffer)
			return n, errors.Trace(err)
		}
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
		if !proxy.config.TunnelMode {
			// Unlike other QUIC uses, which carry end-to-end SSH, fallback
			// mode relies on the stream EOF to signal end of data, and a
			// QUIC Close discards data the client has not yet read.
			//
			// There is no timeout, so a slow client can read all the data.
			// The wait ends when the client closes the connection, or when
			// the client relay ends, including on inactivity timeout, and
			// the handleCtx AfterFunc closes lightConn.
			if quicConn, ok := conn.(*quic.Conn); ok {
				quicConn.GracefulShutdown(0)
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

// dialTunnelServer establishes the upstream connection and sends the report.
func (proxy *Proxy) dialTunnelServer(
	ctx context.Context,
	header *lightHeader,
	clientIP string,
	ingressProtocol string,
	ingressSNI string,
	ingressTLSClientHelloFragmented bool,
	ingressTLSPadding int,
	ingressDidResume bool,
	isPersonal bool) (
	conn net.Conn,
	destinationAddress string,
	completedTCP time.Time,
	completedTLS time.Time,
	completedQUIC time.Time,
	retErr error) {

	dialCtx, cancel := context.WithTimeout(
		ctx, proxy.upstreamDialTimeout)
	defer cancel()

	authorization, destinationAddress, err :=
		proxy.verifyTunnelDialAuthorization(header)
	if err != nil {
		return nil, "", completedTCP, completedTLS, completedQUIC, errors.Trace(err)
	}

	// The destination is the IP address in the dial authorization.
	if proxy.isDisallowedIP(net.IP(authorization.IPAddress)) {

		return nil, destinationAddress, completedTCP, completedTLS, completedQUIC, errors.TraceNew("IP is bogon or proxy address")
	}

	var exporter []byte

	switch header.EgressProtocol {
	case TransportTLS:
		if proxy.config.ProxyTLSDialer == nil {
			return nil, destinationAddress, completedTCP, completedTLS, completedQUIC, errors.TraceNew("missing proxy TLS dialer")
		}
		conn, exporter, completedTCP, completedTLS, err =
			proxy.dialTunnelServerTLS(
				dialCtx, header, authorization, destinationAddress)
	case TransportQUIC:
		if proxy.config.ProxyQUICDialer == nil {
			return nil, destinationAddress, completedTCP, completedTLS, completedQUIC, errors.TraceNew("missing proxy QUIC dialer")
		}
		conn, exporter, completedQUIC, err =
			proxy.dialTunnelServerQUIC(
				dialCtx, header, authorization, destinationAddress)
	default:
		return nil, destinationAddress, completedTCP, completedTLS, completedQUIC, errors.TraceNew("unsupported egress protocol")
	}
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		return nil, destinationAddress, completedTCP, completedTLS, completedQUIC, errors.Trace(err)
	}
	if conn == nil {
		return nil, destinationAddress, completedTCP, completedTLS, completedQUIC, errors.TraceNew(
			"missing proxy tunnel connection")
	}
	if err := validateTunnelProxyReportExporter(exporter); err != nil {
		conn.Close()
		return nil, destinationAddress, completedTCP, completedTLS, completedQUIC, errors.Trace(err)
	}
	exporter = append([]byte(nil), exporter...)

	tunnelConn := conn
	unassociateAfter := context.AfterFunc(dialCtx, func() {
		tunnelConn.Close()
	})
	defer unassociateAfter()

	err = proxy.writeTunnelProxyReport(
		conn,
		exporter,
		header,
		clientIP,
		ingressProtocol,
		ingressSNI,
		ingressTLSClientHelloFragmented,
		ingressTLSPadding,
		ingressDidResume,
		isPersonal)

	// Detach the dial timeout before handing the connection to the relay.
	unassociateAfter()
	if err == nil {
		err = dialCtx.Err()
	}
	if err != nil {
		conn.Close()
		return nil, destinationAddress, completedTCP, completedTLS, completedQUIC, errors.Trace(err)
	}

	return conn, destinationAddress, completedTCP, completedTLS, completedQUIC, nil
}

func (proxy *Proxy) verifyTunnelDialAuthorization(
	header *lightHeader) (*TunnelDialAuthorization, string, error) {

	if header.DestinationAddress != "" {
		return nil, "", errors.TraceNew("unexpected destination address")
	}

	authorization, err := VerifyTunnelDialAuthorization(
		proxy.tunnelDialAuthorizationPublicKey,
		header.TunnelDialAuthorization)
	if err != nil {
		return nil, "", errors.Trace(err)
	}

	destinationAddress, err := getTunnelDestinationAddress(
		authorization, header.EgressProtocol)
	if err != nil {
		return nil, "", errors.Trace(err)
	}
	if len(header.EgressSNI) > maxTunnelSNI {
		return nil, "", errors.TraceNew("invalid egress SNI")
	}

	return authorization, destinationAddress, nil
}

// dialTunnelServerQUIC establishes the upstream QUIC connection.
func (proxy *Proxy) dialTunnelServerQUIC(
	ctx context.Context,
	header *lightHeader,
	authorization *TunnelDialAuthorization,
	destinationAddress string) (
	conn net.Conn,
	exporter []byte,
	completedQUIC time.Time,
	retErr error) {

	if header.EgressTLSProfile != 0 ||
		len(header.EgressRandomizedTLSProfileSeed) != 0 {

		return nil, nil, completedQUIC, errors.TraceNew(
			"unexpected egress TLS parameters")
	}

	quicVersion := decodeQUICVersion(header.EgressQUICVersion)
	if quicVersion == "" ||
		!common.Contains(protocol.SupportedQUICv1Versions, quicVersion) {

		return nil, nil, completedQUIC, errors.TraceNew("invalid egress QUIC version")
	}
	var rootSeed *prng.Seed
	if len(header.EgressQUICDialRootObfuscationSeed) > 0 {
		if len(header.EgressQUICDialRootObfuscationSeed) != prng.SEED_LENGTH {
			return nil, nil, completedQUIC, errors.TraceNew(
				"invalid egress QUIC dial root obfuscation seed")
		}
		rootSeed = new(prng.Seed)
		copy(rootSeed[:], header.EgressQUICDialRootObfuscationSeed)
	}

	needsRootSeed := protocol.QUICVersionHasRandomizedClientHello(quicVersion) ||
		protocol.QUICVersionIsObfuscated(quicVersion)
	if needsRootSeed && rootSeed == nil {
		return nil, nil, completedQUIC, errors.TraceNew(
			"missing egress QUIC dial root obfuscation seed")
	}
	if !needsRootSeed && rootSeed != nil {
		return nil, nil, completedQUIC, errors.TraceNew(
			"unexpected egress QUIC dial root obfuscation seed")
	}

	var clientHelloSeed, paddingSeed *prng.Seed
	var err error
	if rootSeed != nil {
		clientHelloSeed, paddingSeed, err =
			deriveQUICDialSeeds(rootSeed, quicVersion)
		if err != nil {
			return nil, nil, completedQUIC, errors.Trace(err)
		}
	}

	obfuscationKey, err := DeriveTunnelQUICObfuscationKey(
		authorization.RootObfuscationSecret)
	if err != nil {
		return nil, nil, completedQUIC, errors.Trace(err)
	}
	verifyPin := base64.StdEncoding.EncodeToString(
		authorization.VerifyPin)

	conn, exporter, completedQUIC, err = proxy.config.ProxyQUICDialer(
		ctx,
		destinationAddress,
		header.EgressSNI,
		quicVersion,
		clientHelloSeed,
		paddingSeed,
		hex.EncodeToString(obfuscationKey),
		verifyPin)

	return conn, exporter, completedQUIC, errors.Trace(err)
}

// dialTunnelServerTLS establishes the upstream TLS connection.
func (proxy *Proxy) dialTunnelServerTLS(
	ctx context.Context,
	header *lightHeader,
	authorization *TunnelDialAuthorization,
	destinationAddress string) (
	conn net.Conn,
	exporter []byte,
	completedTCP time.Time,
	completedTLS time.Time,
	retErr error) {

	if header.EgressQUICVersion != 0 {
		return nil, nil, completedTCP, completedTLS, errors.TraceNew(
			"unexpected egress QUIC version")
	}
	if len(header.EgressQUICDialRootObfuscationSeed) != 0 {
		return nil, nil, completedTCP, completedTLS, errors.TraceNew(
			"unexpected egress QUIC dial root obfuscation seed")
	}

	tlsProfile := decodeTLSProfile(header.EgressTLSProfile)
	if tlsProfile == "" {
		return nil, nil, completedTCP, completedTLS, errors.TraceNew("invalid egress TLS profile")
	}
	var randomizedTLSProfileSeed *prng.Seed
	if len(header.EgressRandomizedTLSProfileSeed) > 0 {
		if len(header.EgressRandomizedTLSProfileSeed) != prng.SEED_LENGTH {
			return nil, nil, completedTCP, completedTLS, errors.TraceNew(
				"invalid egress randomized TLS profile seed")
		}
		randomizedTLSProfileSeed = new(prng.Seed)
		copy(
			randomizedTLSProfileSeed[:],
			header.EgressRandomizedTLSProfileSeed)
	}
	if protocol.TLSProfileIsRandomized(tlsProfile) {
		if randomizedTLSProfileSeed == nil {
			return nil, nil, completedTCP, completedTLS, errors.TraceNew(
				"missing egress randomized TLS profile seed")
		}
	} else if randomizedTLSProfileSeed != nil {
		return nil, nil, completedTCP, completedTLS, errors.TraceNew(
			"unexpected egress randomized TLS profile seed")
	}

	supportsTLS13, err := tlsdialer.TLSProfileSupportsTLS13(
		tlsProfile, randomizedTLSProfileSeed)
	if err != nil {
		return nil, nil, completedTCP, completedTLS, errors.Trace(err)
	}
	if !supportsTLS13 {
		return nil, nil, completedTCP, completedTLS, errors.TraceNew(
			"egress TLS profile does not support TLS 1.3")
	}

	passthroughKey, err := DeriveTunnelTLSPassthroughKey(
		authorization.RootObfuscationSecret)
	if err != nil {
		return nil, nil, completedTCP, completedTLS, errors.Trace(err)
	}
	passthroughMessage, err := obfuscator.MakeTLSPassthroughMessage(
		true,
		hex.EncodeToString(passthroughKey))
	if err != nil {
		return nil, nil, completedTCP, completedTLS, errors.Trace(err)
	}

	verifyPin := base64.StdEncoding.EncodeToString(
		authorization.VerifyPin)

	// Future enhancement: egress TLS fragmentation and padding. These should
	// be selected by the proxy, using its own tactics, which are appropriate
	// for the proxy's location, and not by the client. A client-supplied
	// seed could make the proxy's selection replayable.
	conn, exporter, completedTCP, completedTLS, err = proxy.config.ProxyTLSDialer(
		ctx,
		destinationAddress,
		tlsProfile,
		randomizedTLSProfileSeed,
		header.EgressSNI,
		false,
		0,
		passthroughMessage,
		verifyPin)

	return conn, exporter, completedTCP, completedTLS, errors.Trace(err)
}

// writeTunnelProxyReport writes a report cryptographically bound to the
// tunnel connection using its TLS or QUIC exporter.
func (proxy *Proxy) writeTunnelProxyReport(
	tunnelConn net.Conn,
	exporter []byte,
	header *lightHeader,
	clientIP string,
	ingressProtocol string,
	ingressSNI string,
	ingressTLSClientHelloFragmented bool,
	ingressTLSPadding int,
	ingressDidResume bool,
	isPersonal bool) error {

	IP := net.ParseIP(clientIP)
	if IP == nil {
		return errors.TraceNew("invalid client IP")
	}
	if IPv4 := IP.To4(); IPv4 != nil {
		IP = IPv4
	}

	var encodedIngressProtocol uint8
	switch ingressProtocol {
	case LIGHT_PROTOCOL_TLS:
		encodedIngressProtocol = TransportTLS
	case LIGHT_PROTOCOL_QUIC:
		encodedIngressProtocol = TransportQUIC
	default:
		return errors.TraceNew("unsupported ingress protocol")
	}

	report := &TunnelProxyReport{
		Version:                         TunnelProxyReportVersion,
		TrustedProxyAuthorization:       proxy.tunnelTrustedProxyAuthorization,
		ClientIP:                        IP,
		ProxyPlatform:                   proxy.tunnelProxyPlatform,
		ProxyVersion:                    proxy.config.ProxyVersion,
		ProxyBuildRev:                   proxy.tunnelProxyBuildRev,
		IngressProtocol:                 encodedIngressProtocol,
		IngressTLSProfile:               header.TLSProfile,
		IngressQUICVersion:              header.QUICVersion,
		IngressSNI:                      ingressSNI,
		IngressTLSClientHelloFragmented: ingressTLSClientHelloFragmented,
		IngressDidResume:                ingressDidResume,
		IngressTLSPadding:               uint16(ingressTLSPadding),
		EgressTLSProfile:                header.EgressTLSProfile,
		EgressQUICVersion:               header.EgressQUICVersion,
		MatchedPersonalCompartments:     isPersonal,
	}

	return errors.Trace(WriteTunnelProxyReport(
		tunnelConn,
		proxy.config.TunnelProxyPrivateKey,
		exporter,
		report,
		proxy.tunnelProxyReportPaddingMinBytes,
		proxy.tunnelProxyReportPaddingMaxBytes))
}

type bytesCounter struct {
	bytesRead      atomic.Int64
	bytesWritten   atomic.Int64
	activityProxy  *Proxy
	activityRegion *regionActivity
}

// assignByteCountsToActivity adds all bytes counted so far to the selected
// personal or common activity counters and directs future byte updates there.
func (counter *bytesCounter) assignByteCountsToActivity(activity *regionActivity) {
	counter.activityRegion = activity
	activity.bytesUp.Add(counter.bytesRead.Load())
	activity.bytesDown.Add(counter.bytesWritten.Load())
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

func (proxy *Proxy) getOrCreateRegionActivity(
	region string, isPersonal bool) *regionActivity {

	if region == "" {
		region = "None"
	}
	mutex := &proxy.commonStatsMutex
	statsMap := proxy.commonRegionActivity
	if isPersonal {
		mutex = &proxy.personalStatsMutex
		statsMap = proxy.personalRegionActivity
	}
	mutex.Lock()
	defer mutex.Unlock()

	stats, ok := statsMap[region]
	if !ok {
		stats = &regionActivity{}
		statsMap[region] = stats
	}
	stats.connectingClients.Add(1)
	return stats
}

func (proxy *Proxy) snapshotAndResetRegionActivity(
	mutex *sync.Mutex,
	statsMap map[string]*regionActivity) map[string]RegionActivitySnapshot {

	mutex.Lock()
	defer mutex.Unlock()

	result := make(map[string]RegionActivitySnapshot, len(statsMap))
	for region, stats := range statsMap {
		// Read counts first so a concurrent disconnect cannot cause an entry
		// with unreported bytes to be pruned.
		snapshot := RegionActivitySnapshot{
			ConnectingClients: stats.connectingClients.Load(),
			ConnectedClients:  stats.connectedClients.Load(),
			BytesUp:           stats.bytesUp.Swap(0),
			BytesDown:         stats.bytesDown.Swap(0),
		}
		if snapshot.BytesUp > 0 || snapshot.BytesDown > 0 ||
			snapshot.ConnectingClients > 0 || snapshot.ConnectedClients > 0 {
			result[region] = snapshot
		} else {
			delete(statsMap, region)
		}
	}
	return result
}

func (proxy *Proxy) activityUpdate(ctx context.Context) {

	ticker := time.NewTicker(proxyActivityUpdatePeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			proxy.emitActivity()
		case <-ctx.Done():
			return
		}
	}
}

func (proxy *Proxy) emitActivity() {
	now := time.Now()
	duration := now.Sub(proxy.lastActivityUpdate)
	proxy.lastActivityUpdate = now

	proxy.eventReceiver.Activity(&ActivityStats{
		ProxyID:                proxy.ID,
		ProxyProviderID:        proxy.config.ProviderID,
		BytesUp:                proxy.activityBytesUp.Swap(0),
		BytesDown:              proxy.activityBytesDown.Swap(0),
		BytesDuration:          duration,
		CurrentConnectionCount: proxy.currentConnectionCount.Load(),
		PersonalRegionActivity: proxy.snapshotAndResetRegionActivity(
			&proxy.personalStatsMutex, proxy.personalRegionActivity),
		CommonRegionActivity: proxy.snapshotAndResetRegionActivity(
			&proxy.commonStatsMutex, proxy.commonRegionActivity),
	})
}

func (proxy *Proxy) acquireProxyLimit(isPersonal bool) (common.ProxyLimitReleaseFunc, error) {

	var release common.ProxyLimitReleaseFunc
	var ok bool

	if isPersonal {
		release, ok = proxy.proxyLimits.TryAcquirePersonalClient()
	} else {
		release, ok = proxy.proxyLimits.TryAcquireCommonClient()
	}

	if !ok {
		return nil, errors.TraceNew("proxy capacity exceeded")
	}

	return release, nil
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

func (proxy *Proxy) isDisallowedIP(IP net.IP) bool {
	if proxy.config.AllowBogons {
		return false
	}
	if common.IsBogon(IP) {
		return true
	}

	// In tunnel mode, the destination comes from a signed tunnel dial
	// authorization, so one of the proxy's own IPs can be reached only at an
	// IP and port that is signed. In fallback mode, the client chooses the
	// destination, and the proxy's own IPs are rejected.
	if proxy.config.TunnelMode {
		return false
	}
	for _, proxyIP := range proxy.proxyIPs {
		if IP.Equal(proxyIP) {
			return true
		}
	}
	return false
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
		return addrs, false, errors.TraceNew("invalid destination port")
	}

	IP := net.ParseIP(host)
	if IP != nil {

		if proxy.isDisallowedIP(IP) {
			return addrs, false, errors.TraceNew("IP is bogon or proxy address")
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

		// Perform the bogon and proxy IP checks here so they don't need to be
		// repeated for cached values.

		for _, ipAddr := range ipAddrs {
			if proxy.isDisallowedIP(ipAddr.IP) {
				return addrs, false, errors.TraceNew("IP is bogon or proxy address")
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
//
// redactingProxyEventReceiver also limits the size of log messages and of
// ConnectionStats values which are, or may include, client-supplied light
// header values. The light header is limited only by its 64K wire size, so
// without this limit an individual client could produce oversized logs.
// Values are not otherwise sanitized; receivers which write line-oriented
// logs must escape these values.
type redactingProxyEventReceiver struct {
	ProxyEventReceiver
}

func newRedactingProxyEventReceiver(
	eventReceiver ProxyEventReceiver) *redactingProxyEventReceiver {

	return &redactingProxyEventReceiver{ProxyEventReceiver: eventReceiver}
}

func (r *redactingProxyEventReceiver) Connection(stats *ConnectionStats) {
	stats.SponsorID = limitLogString(stats.SponsorID)
	stats.ClientBuildRev = limitLogString(stats.ClientBuildRev)
	stats.DeviceRegion = limitLogString(stats.DeviceRegion)
	stats.SessionID = limitLogString(stats.SessionID)
	stats.DestinationAddress = limitLogString(stats.DestinationAddress)
	stats.SNI = limitLogString(stats.SNI)
	stats.Failure = redactAndLimitLogString(stats.Failure)
	r.ProxyEventReceiver.Connection(stats)
}

func (r *redactingProxyEventReceiver) DebugLog(proxyID string, message string) {
	r.ProxyEventReceiver.DebugLog(proxyID, redactAndLimitLogString(message))
}

func (r *redactingProxyEventReceiver) InfoLog(proxyID string, message string) {
	r.ProxyEventReceiver.InfoLog(proxyID, redactAndLimitLogString(message))
}

func (r *redactingProxyEventReceiver) WarningLog(proxyID string, message string) {
	r.ProxyEventReceiver.WarningLog(proxyID, redactAndLimitLogString(message))
}

func (r *redactingProxyEventReceiver) ErrorLog(proxyID string, message string) {
	r.ProxyEventReceiver.ErrorLog(proxyID, redactAndLimitLogString(message))
}

func limitLogString(value string) string {
	return common.TruncateUTF8String(value, maxLogStringLength)
}

func redactAndLimitLogString(value string) string {
	return limitLogString(common.RedactIPAddressesString(value))
}
