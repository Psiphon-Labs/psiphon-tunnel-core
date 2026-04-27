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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tls "github.com/Psiphon-Labs/psiphon-tls"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/obfuscator"
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
	defaultRateLimitQuantity        = 10000
	defaultRateLimitInterval        = 1 * time.Minute
	defaultMaxConcurrent            = 10000
)

// ProxyConfig specifies the configuration of a light proxy.
type ProxyConfig struct {
	Protocol            string   `json:",omitempty"`
	ProviderID          string   `json:",omitempty"`
	ListenAddress       string   `json:",omitempty"`
	DialAddress         string   `json:",omitempty"`
	ObfuscationKey      string   `json:",omitempty"`
	TLSCertificate      []byte   `json:",omitempty"`
	TLSPrivateKey       []byte   `json:",omitempty"`
	PassthroughAddress  string   `json:",omitempty"`
	AllowedDestinations []string `json:",omitempty"`
	InactivityTimeout   string   `json:",omitempty"`
	UpstreamDialTimeout string   `json:",omitempty"`
	RelayBufferSize     int      `json:",omitempty"`
	RateLimitQuantity   *int     `json:",omitempty"`
	RateLimitInterval   string   `json:",omitempty"`
	MaxConcurrent       *int     `json:",omitempty"`
}

// ProxyEventReceiver receives event callbacks from a light proxy, and handles
// logging and stats shipping.
type ProxyEventReceiver interface {
	Listening(address string)

	Connection(stats *ConnectionStats)

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
	config                *ProxyConfig
	lookupGeoIP           LookupGeoIP
	eventReceiver         ProxyEventReceiver
	ID                    string
	proxyGeoIPData        common.GeoIPData
	tlsConfig             *tls.Config
	obfuscatorSeedHistory *obfuscator.SeedHistory
	allowedDestinations   common.StringLookup
	inactivityTimeout     time.Duration
	upstreamDialTimeout   time.Duration
	relayBufferSize       int
	rateLimitQuantity     int
	rateLimitInterval     time.Duration
	maxConcurrent         int

	limitsMutex           sync.Mutex
	concurrentConnections map[string]int
	rateLimiters          *lrucache.Cache

	connectionNumber atomic.Int64
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

	if len(config.AllowedDestinations) == 0 {
		return nil, errors.TraceNew("missing allowed destinations")
	}
	normalizedAllowedDestinations := make([]string, len(config.AllowedDestinations))
	for i, address := range config.AllowedDestinations {
		var err error
		normalizedAllowedDestinations[i], err = normalizeDestinationAddress(address)
		if err != nil {
			return nil, errors.Trace(err)
		}
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

	if (config.RateLimitQuantity != nil) != (config.RateLimitInterval != "") ||
		(config.RateLimitQuantity != nil && *config.RateLimitQuantity < 0) ||
		(config.MaxConcurrent != nil && *config.MaxConcurrent < 0) {
		return nil, errors.TraceNew("invalid limits")
	}

	rateLimitQuantity := defaultRateLimitQuantity
	if config.RateLimitQuantity != nil {
		rateLimitQuantity = *config.RateLimitQuantity
	}

	rateLimitInterval := defaultRateLimitInterval
	if config.RateLimitInterval != "" {
		var err error
		rateLimitInterval, err = time.ParseDuration(config.RateLimitInterval)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	maxConcurrent := defaultMaxConcurrent
	if config.MaxConcurrent != nil {
		maxConcurrent = *config.MaxConcurrent
	}

	host, _, err := net.SplitHostPort(config.DialAddress)
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

	proxy := &Proxy{
		config:                config,
		lookupGeoIP:           lookupGeoIP,
		eventReceiver:         eventReceiver,
		ID:                    makeProxyID(config.DialAddress, config.ObfuscationKey),
		proxyGeoIPData:        proxyGeoIPData,
		tlsConfig:             tlsConfig,
		obfuscatorSeedHistory: obfuscator.NewSeedHistory(nil),
		allowedDestinations:   common.NewStringLookup(normalizedAllowedDestinations),
		inactivityTimeout:     inactivityTimeout,
		upstreamDialTimeout:   upstreamDialTimeout,
		relayBufferSize:       relayBufferSize,
		rateLimitQuantity:     rateLimitQuantity,
		rateLimitInterval:     rateLimitInterval,
		maxConcurrent:         maxConcurrent,
		concurrentConnections: make(map[string]int),
		rateLimiters: lrucache.NewWithLRU(
			0,
			rateLimiterReapHistoryFrequency,
			rateLimiterMaxCacheEntries),
	}

	tlsConfig.PassthroughAddress = config.PassthroughAddress

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
		TTL := obfuscator.TLS_PASSTHROUGH_TIME_PERIOD

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

// Run runs the proxy until the specified context is done.
func (proxy *Proxy) Run(ctx context.Context) error {

	// Future enhancement: use psiphon/server.newTCPListenerWithBPF.
	listenConfig := &net.ListenConfig{}
	listener, err := listenConfig.Listen(
		context.Background(), "tcp", proxy.config.ListenAddress)
	if err != nil {
		return errors.Trace(err)
	}

	proxy.eventReceiver.Listening(listener.Addr().String())

	waitGroup := new(sync.WaitGroup)

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
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				proxy.handleConn(ctx, conn)
			}()
		}
	}()

	<-ctx.Done()
	listener.Close()
	waitGroup.Wait()

	return nil
}

func (proxy *Proxy) handleConn(ctx context.Context, conn net.Conn) {
	err := proxy.handleConnWithErr(ctx, conn)
	if err != nil && ctx.Err() == nil {
		proxy.eventReceiver.WarningLog(
			proxy.ID, errors.Trace(err).Error())
	}
}

func (proxy *Proxy) handleConnWithErr(ctx context.Context, conn net.Conn) (retErr error) {

	defer conn.Close()

	var geoIPData common.GeoIPData
	completedTCP := time.Now().UTC()
	var completedTLS time.Time
	var clientSNI string
	bytesCounter := &bytesCounter{}
	var completedLightHeader time.Time
	var header *lightHeader
	var normalizedDestinationAddress string
	var completedUpstreamDial time.Time

	connectionNum := proxy.connectionNumber.Add(1)

	// Connection stats are emitted on connection end, including for any
	// failures after this point.
	defer func() {

		var sponsorID, clientPlatform, clientBuildRev, clientID string
		var deviceRegion, sessionID, networkType, tlsProfile string
		var proxyEntryTracker, clientConnectionNum int64
		var clientTCPDuration, clientTLSDuration time.Duration

		if header != nil {
			// The sponsor ID is uppercase by convention; the case lost in
			// header binary encoding.
			sponsorID = strings.ToUpper(hex.EncodeToString(header.SponsorID))
			clientPlatform = decodeClientPlatform(header.ClientPlatform)
			clientBuildRev = hex.EncodeToString(header.ClientBuildRev)
			clientID = hex.EncodeToString(header.ClientID)
			deviceRegion = header.DeviceRegion
			sessionID = hex.EncodeToString(header.SessionID)
			proxyEntryTracker = header.ProxyEntryTracker
			networkType = decodeNetworkType(header.NetworkType)
			clientConnectionNum = header.ConnectionNum
			tlsProfile = decodeTLSProfile(header.TLSProfile)
			clientTCPDuration = time.Duration(header.TCPDuration)
			clientTLSDuration = time.Duration(header.TLSDuration)
		}

		stats := &ConnectionStats{
			ProxyID:                    proxy.ID,
			ProxyProviderID:            proxy.config.ProviderID,
			ProxyGeoIPData:             proxy.proxyGeoIPData,
			ProxyConnectionNum:         connectionNum,
			ClientGeoIPData:            geoIPData,
			SponsorID:                  sponsorID,
			ClientPlatform:             clientPlatform,
			ClientBuildRev:             clientBuildRev,
			ClientID:                   clientID,
			DeviceRegion:               deviceRegion,
			SessionID:                  sessionID,
			ProxyEntryTracker:          proxyEntryTracker,
			NetworkType:                networkType,
			ClientConnectionNum:        clientConnectionNum,
			DestinationAddress:         normalizedDestinationAddress,
			TLSProfile:                 tlsProfile,
			SNI:                        clientSNI,
			ClientTCPDuration:          clientTCPDuration,
			ClientTLSDuration:          clientTLSDuration,
			ProxyCompletedTCP:          completedTCP,
			ProxyCompletedTLS:          completedTLS,
			ProxyCompletedLightHeader:  completedLightHeader,
			ProxyCompletedUpstreamDial: completedUpstreamDial,
			BytesRead:                  bytesCounter.bytesRead.Load(),
			BytesWritten:               bytesCounter.bytesWritten.Load(),
			ConnectionFailure:          retErr,
		}

		proxy.eventReceiver.Connection(stats)
	}()

	clientIP, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return errors.Trace(err)
	}

	geoIPData = proxy.lookupGeoIP(clientIP)

	activityConn, err := common.NewActivityMonitoredConn(
		conn,
		proxy.inactivityTimeout,
		false,
		nil,
		bytesCounter)
	if err != nil {
		return errors.Trace(err)
	}

	tlsConn := tls.Server(activityConn, proxy.tlsConfig)

	tlsDone := make(chan struct{})
	tlsWaitGroup := new(sync.WaitGroup)
	tlsWaitGroup.Add(1)
	go func() {
		// Interrupt TLS handshake or header read on ctx done.
		defer tlsWaitGroup.Done()
		select {
		case <-ctx.Done():
			activityConn.Close()
		case <-tlsDone:
		}
	}()

	err = tlsConn.Handshake()
	if err != nil {
		close(tlsDone)
		tlsWaitGroup.Wait()
		return errors.Trace(err)
	}

	// Future enhancement: it's possible to record the SNI even if the TLS
	// handshake fails, via tlsConfig.GetConfigForClient. This requires a
	// tlsConfig.Clone(); note that there's currently a bug in
	// psiphon-tls.Config.Clone, where it fails to copy the passthrough
	// configuration.

	clientSNI = tlsConn.ConnectionState().ServerName
	completedTLS = time.Now().UTC()

	lightConn := newLightConn(tlsConn, nil)

	header, err = lightConn.readHeader()
	if err != nil {
		close(tlsDone)
		tlsWaitGroup.Wait()
		return errors.Trace(err)
	}

	completedLightHeader = time.Now().UTC()

	close(tlsDone)
	tlsWaitGroup.Wait()

	// Apply limits after reading the header so that the ConnectionFailure
	// will be accompanied by client characteristics such as sponsor ID. A
	// later enforcement also means the client is authenticated as having the
	// obfuscation key, and a prober behind shared NAT can't consume limits.

	err = proxy.applyRateLimit(clientIP)
	if err != nil {
		return errors.Trace(err)
	}

	err = proxy.takeMaxConcurrent(clientIP)
	if err != nil {
		return errors.Trace(err)
	}
	defer proxy.replaceMaxConcurrent(clientIP)

	normalizedDestinationAddress, err = normalizeDestinationAddress(header.DestinationAddress)
	if err != nil {
		return errors.Trace(err)
	}
	if !proxy.allowedDestinations.Contains(normalizedDestinationAddress) {
		return errors.TraceNew("disallowed destination")
	}

	dialCtx, dialCancel := context.WithTimeout(ctx, proxy.upstreamDialTimeout)
	upstreamConn, err := (&net.Dialer{}).DialContext(
		dialCtx, "tcp", normalizedDestinationAddress)
	dialCancel()
	if err != nil {
		return errors.Trace(err)
	}

	completedUpstreamDial = time.Now().UTC()

	// TODO: optionally send PROXY protocol header to destination. See
	// addProxyProtocolHeader in psiphon/server.sshClient.handleTCPChannel.

	relayCtx, cancel := context.WithCancel(ctx)

	relayWaitGroup := new(sync.WaitGroup)

	relayWaitGroup.Add(1)
	go func() {
		// Interrupt relay on ctx done.
		defer relayWaitGroup.Done()
		<-relayCtx.Done()
		lightConn.Close()
		upstreamConn.Close()
	}()

	relayWaitGroup.Add(1)
	go func() {
		defer relayWaitGroup.Done()
		_, err := common.CopyBuffer(
			lightConn, upstreamConn, make([]byte, proxy.relayBufferSize))
		if err != nil && ctx.Err() == nil {
			// Debug since errors such as "connection reset by peer" occur
			// during normal operation
			proxy.eventReceiver.DebugLog(proxy.ID, errors.Trace(err).Error())
		}
		lightConn.Close()
	}()
	_, err = common.CopyBuffer(
		upstreamConn, lightConn, make([]byte, proxy.relayBufferSize))
	if err != nil && ctx.Err() == nil {
		proxy.eventReceiver.DebugLog(proxy.ID, errors.Trace(err).Error())
	}
	upstreamConn.Close()
	cancel()
	relayWaitGroup.Wait()

	return nil
}

func (proxy *Proxy) applyRateLimit(clientIP string) error {

	if proxy.rateLimitQuantity <= 0 || proxy.rateLimitInterval <= 0 {
		return nil
	}

	proxy.limitsMutex.Lock()
	defer proxy.limitsMutex.Unlock()

	var rateLimiter *rate.Limiter

	entry, ok := proxy.rateLimiters.Get(clientIP)
	if ok {
		rateLimiter = entry.(*rate.Limiter)
	} else {
		limit := float64(proxy.rateLimitQuantity) / proxy.rateLimitInterval.Seconds()
		rateLimiter = rate.NewLimiter(rate.Limit(limit), proxy.rateLimitQuantity)
		proxy.rateLimiters.Set(clientIP, rateLimiter, proxy.rateLimitInterval)
	}

	if !rateLimiter.Allow() {
		return errors.Trace(std_errors.New("rate limit exceeded"))
	}

	return nil
}

func (proxy *Proxy) takeMaxConcurrent(clientIP string) error {

	if proxy.maxConcurrent <= 0 {
		return nil
	}

	proxy.limitsMutex.Lock()
	defer proxy.limitsMutex.Unlock()

	count := proxy.concurrentConnections[clientIP]
	if count >= proxy.maxConcurrent {
		return errors.TraceNew("max concurrent exceeded")
	}
	proxy.concurrentConnections[clientIP] = count + 1

	return nil
}

func (proxy *Proxy) replaceMaxConcurrent(clientIP string) {

	if proxy.maxConcurrent <= 0 {
		return
	}

	proxy.limitsMutex.Lock()
	defer proxy.limitsMutex.Unlock()

	count := proxy.concurrentConnections[clientIP] - 1
	if count <= 0 {
		delete(proxy.concurrentConnections, clientIP)
	} else {
		proxy.concurrentConnections[clientIP] = count
	}
}
