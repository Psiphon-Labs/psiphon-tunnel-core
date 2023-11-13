//go:build PSIPHON_ENABLE_REFRACTION_NETWORKING
// +build PSIPHON_ENABLE_REFRACTION_NETWORKING

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

/*
Package refraction wraps github.com/refraction-networking/gotapdance with
net.Listener and net.Conn types that provide drop-in integration with Psiphon.
*/
package refraction

import (
	"context"
	std_errors "errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/armon/go-proxyproto"
	lrucache "github.com/cognusion/go-cache-lru"
	"github.com/pion/sctp"
	refraction_networking_assets "github.com/refraction-networking/conjure/pkg/client/assets"
	refraction_networking_registration "github.com/refraction-networking/conjure/pkg/registrars/registration"
	refraction_networking_transports "github.com/refraction-networking/conjure/pkg/transports/client"
	refraction_networking_dtls "github.com/refraction-networking/conjure/pkg/transports/connecting/dtls"
	refraction_networking_prefix "github.com/refraction-networking/conjure/pkg/transports/wrapping/prefix"
	refraction_networking_proto "github.com/refraction-networking/conjure/proto"
	refraction_networking_client "github.com/refraction-networking/gotapdance/tapdance"
)

const (
	READ_PROXY_PROTOCOL_HEADER_TIMEOUT = 5 * time.Second
	REGISTRATION_CACHE_MAX_ENTRIES     = 256
)

// Enabled indicates if Refraction Networking functionality is enabled.
func Enabled() bool {
	return true
}

// Listener is a net.Listener.
type Listener struct {
	net.Listener
}

// Listen creates a new Refraction Networking listener.
//
// The Refraction Networking station (TapDance or Conjure) will send the
// original client address via the HAProxy proxy protocol v1,
// https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt. The original
// client address is read and returned by accepted conns' RemoteAddr.
// RemoteAddr _must_ be called non-concurrently before calling Read on
// accepted conns as the HAProxy proxy protocol header reading logic sets
// SetReadDeadline and performs a Read.
//
// Psiphon server hosts should be configured to accept tunnel connections only
// from Refraction Networking stations.
func Listen(address string) (net.Listener, error) {

	tcpListener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Setting a timeout ensures that reading the proxy protocol
	// header completes or times out and RemoteAddr will not block. See:
	// https://godoc.org/github.com/armon/go-proxyproto#Conn.RemoteAddr

	proxyListener := &proxyproto.Listener{
		Listener:           tcpListener,
		ProxyHeaderTimeout: READ_PROXY_PROTOCOL_HEADER_TIMEOUT}

	stationListener := &stationListener{
		proxyListener: proxyListener,
	}

	return &Listener{Listener: stationListener}, nil
}

// stationListener uses the proxyproto.Listener SourceCheck callback to
// capture and record the direct remote address, the station address, and
// wraps accepted conns to provide station address metrics via GetMetrics.
// These metrics enable identifying which station fronted a connection, which
// is useful for network operations and troubleshooting.
//
// go-proxyproto.Conn.RemoteAddr reports the originating client IP address,
// which is geolocated and recorded for metrics. The underlying conn's remote
// address, the station address, is not accessible via the go-proxyproto API.
//
// stationListener is not safe for concurrent access.
type stationListener struct {
	proxyListener *proxyproto.Listener
}

func (l *stationListener) Accept() (net.Conn, error) {
	var stationRemoteAddr net.Addr
	l.proxyListener.SourceCheck = func(addr net.Addr) (bool, error) {
		stationRemoteAddr = addr
		return true, nil
	}
	conn, err := l.proxyListener.Accept()
	if err != nil {
		return nil, err
	}
	if stationRemoteAddr == nil {
		return nil, errors.TraceNew("missing station address")
	}
	return &stationConn{
		Conn:             conn,
		stationIPAddress: common.IPAddressFromAddr(stationRemoteAddr),
	}, nil
}

func (l *stationListener) Close() error {
	return l.proxyListener.Close()
}

func (l *stationListener) Addr() net.Addr {
	return l.proxyListener.Addr()
}

type stationConn struct {
	net.Conn
	stationIPAddress string
}

// IrregularTunnelError implements the common.IrregularIndicator interface.
func (c *stationConn) IrregularTunnelError() error {

	// We expect a PROXY protocol header, but go-proxyproto does not produce an
	// error if the "PROXY " prefix is absent; instead the connection will
	// proceed. To detect this case, check if the go-proxyproto RemoteAddr IP
	// address matches the underlying connection IP address. When these values
	// match, there was no PROXY protocol header.
	//
	// Limitation: the values will match if there is a PROXY protocol header
	// containing the same IP address as the underlying connection. This is not
	// an expected case.

	if common.IPAddressFromAddr(c.RemoteAddr()) == c.stationIPAddress {
		return errors.TraceNew("unexpected station IP address")
	}
	return nil
}

// GetMetrics implements the common.MetricsSource interface.
func (c *stationConn) GetMetrics() common.LogFields {

	logFields := make(common.LogFields)

	// Ensure we don't log a potential non-station IP address.
	if c.IrregularTunnelError() == nil {
		logFields["station_ip_address"] = c.stationIPAddress
	}

	return logFields
}

// DialTapDance establishes a new TapDance connection to a TapDance station
// specified in the config assets and forwarding through to the Psiphon server
// specified by address.
//
// The TapDance station config assets (which are also the Conjure station
// assets) are read from dataDirectory/"refraction-networking". When no config
// is found, default assets are paved.
//
// dialer specifies the custom dialer for underlying TCP dials.
//
// The input ctx is expected to have a timeout for the dial.
//
// Limitation: the parameters emitLogs and dataDirectory are used for one-time
// initialization and are ignored after the first DialTapDance/Conjure call.
func DialTapDance(
	ctx context.Context,
	emitLogs bool,
	dataDirectory string,
	dialer Dialer,
	address string) (net.Conn, error) {

	// TapDance is disabled. See comment for protocol.DisabledTunnelProtocols.
	// With that DisabledTunnelProtocols configuration, clients should not
	// reach this error.
	//
	// Note that in addition to this entry point being disabled, the TapDance
	// ClientConf is no longer initialized in initRefractionNetworking below.

	return nil, errors.TraceNew("not supported")

	// return dial(
	// 	ctx,
	//	emitLogs,
	//	dataDirectory,
	//	dialer,
	//	address,
	//	nil)
}

// DialConjure establishes a new Conjure connection to a Conjure station.
//
// dialer specifies the custom dialer to use for phantom dials. Additional
// Conjure-specific parameters are specified in conjureConfig.
//
// See DialTapdance comment.
func DialConjure(
	ctx context.Context,
	emitLogs bool,
	dataDirectory string,
	dialer Dialer,
	address string,
	conjureConfig *ConjureConfig) (net.Conn, error) {

	return dial(
		ctx,
		emitLogs,
		dataDirectory,
		dialer,
		address,
		conjureConfig)
}

func dial(
	ctx context.Context,
	emitLogs bool,
	dataDirectory string,
	dialer Dialer,
	address string,
	conjureConfig *ConjureConfig) (net.Conn, error) {

	err := initRefractionNetworking(emitLogs, dataDirectory)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.TraceNew("dial context has no timeout")
	}

	useConjure := conjureConfig != nil

	manager := newDialManager()

	refractionDialer := &refraction_networking_client.Dialer{
		DialerWithLaddr: manager.makeManagedDialer(dialer),
		V6Support:       conjureConfig.EnableIPv6Dials,
		UseProxyHeader:  true,
	}

	conjureMetricCached := false
	conjureMetricDelay := time.Duration(0)
	conjureMetricTransport := ""
	conjureMetricPrefix := ""
	conjureMetricSTUNServerAddress := ""

	var conjureCachedRegistration *refraction_networking_client.ConjureReg
	var conjureRecordRegistrar *recordRegistrar

	if useConjure {

		// Our strategy is to try one registration per dial attempt: a cached
		// registration, if it exists, or API or decoy registration, as configured.
		// This assumes Psiphon establishment will try/retry many candidates as
		// required, and that the desired mix of API/decoy registrations will be
		// configured and generated. In good network conditions, internal gotapdance
		// retries (via APIRegistrar.MaxRetries or APIRegistrar.SecondaryRegistrar)
		// are unlikely to start before the Conjure dial is canceled.

		// Caching registrations reduces average Conjure dial time by often
		// eliminating the registration phase. This is especially impactful for
		// short duration tunnels, such as on mobile. Caching also reduces domain
		// fronted traffic and load on the API registrar and decoys.
		//
		// We implement a simple in-memory registration cache with the following
		// behavior:
		//
		// - If a new registration succeeds, but the overall Conjure dial is
		//   _canceled_, the registration is optimistically cached.
		// - If the Conjure phantom dial fails, any associated cached registration
		//   is discarded.
		// - A cached registration's TTL is extended upon phantom dial success.
		// - If the configured TTL changes, the cache is cleared.
		//
		// Limitations:
		// - The cache is not persistent.
		// - There is no TTL extension during a long connection.
		// - Caching a successful registration when the phantom dial is canceled may
		//   skip the necessary "delay" step (however, an immediate re-establishment
		//   to the same candidate is unlikely in this case).
		//
		// TODO:
		// - Revisit when gotapdance adds its own caching.
		// - Consider "pre-registering" Conjure when already connected with a
		//   different protocol, so a Conjure registration is available on the next
		//   establishment; in this scenario, a tunneled API registration would not
		//   require domain fronting.

		refractionDialer.DarkDecoy = true

		// The pop operation removes the registration from the cache. This
		// eliminates the possibility of concurrent candidates (with the same cache
		// key) using and modifying the same registration, a potential race
		// condition. The popped cached registration must be reinserted in the cache
		// after canceling or success, but not on phantom dial failure.

		conjureCachedRegistration = conjureRegistrationCache.pop(conjureConfig)

		if conjureCachedRegistration != nil {

			refractionDialer.DarkDecoyRegistrar = &cachedRegistrar{
				registration: conjureCachedRegistration,
			}

			conjureMetricCached = true
			conjureMetricDelay = 0 // report no delay

		} else if conjureConfig.APIRegistrarBidirectionalURL != "" {

			if conjureConfig.APIRegistrarHTTPClient == nil {
				// While not a guaranteed check, if the APIRegistrarHTTPClient isn't set
				// then the API registration would certainly be unfronted, resulting in a
				// fingerprintable connection leak.
				return nil, errors.TraceNew("missing APIRegistrarHTTPClient")
			}

			refractionDialer.DarkDecoyRegistrar, err = refraction_networking_registration.NewAPIRegistrar(
				&refraction_networking_registration.Config{
					Target:        conjureConfig.APIRegistrarBidirectionalURL,
					Bidirectional: true,
					Delay:         conjureConfig.APIRegistrarDelay,
					MaxRetries:    0,
					HTTPClient:    conjureConfig.APIRegistrarHTTPClient,
				})
			if err != nil {
				return nil, errors.Trace(err)
			}

			conjureMetricDelay = conjureConfig.APIRegistrarDelay

		} else if conjureConfig.DoDecoyRegistration {

			refractionDialer.DarkDecoyRegistrar = refraction_networking_registration.NewDecoyRegistrar()

			refractionDialer.Width = conjureConfig.DecoyRegistrarWidth

			// Limitation: the decoy registration delay is not currently exposed in the
			// gotapdance API.
			conjureMetricDelay = -1 // don't report delay

		} else {

			return nil, errors.TraceNew("no conjure registrar specified")
		}

		if conjureCachedRegistration == nil && conjureConfig.RegistrationCacheTTL != 0 {

			// Record the registration result in order to cache it.
			conjureRecordRegistrar = &recordRegistrar{
				registrar: refractionDialer.DarkDecoyRegistrar,
			}
			refractionDialer.DarkDecoyRegistrar = conjureRecordRegistrar
		}

		// Conjure transport replay limitations:
		//
		// - For CONJURE_TRANSPORT_PREFIX_OSSH, the selected prefix is not replayed
		// - For all transports, randomized port selection is not replayed

		randomizeDstPort := conjureConfig.EnablePortRandomization
		disableOverrides := !conjureConfig.EnableRegistrationOverrides

		conjureMetricTransport = conjureConfig.Transport

		switch conjureConfig.Transport {

		case protocol.CONJURE_TRANSPORT_MIN_OSSH:

			transport, ok := refraction_networking_transports.GetTransportByID(
				refraction_networking_proto.TransportType_Min)
			if !ok {
				return nil, errors.TraceNew("missing min transport")
			}

			config, err := refraction_networking_transports.NewWithParams(
				transport.Name(),
				&refraction_networking_proto.GenericTransportParams{
					RandomizeDstPort: &randomizeDstPort})
			if err != nil {
				return nil, errors.Trace(err)
			}

			refractionDialer.Transport = transport.ID()
			refractionDialer.TransportConfig = config
			refractionDialer.DisableRegistrarOverrides = disableOverrides
			refractionDialer.DialerWithLaddr = newWriteMergeDialer(
				refractionDialer.DialerWithLaddr, false, 32)

		case protocol.CONJURE_TRANSPORT_PREFIX_OSSH:

			transport, ok := refraction_networking_transports.GetTransportByID(
				refraction_networking_proto.TransportType_Prefix)
			if !ok {
				return nil, errors.TraceNew("missing prefix transport")
			}

			prefixID := int32(refraction_networking_prefix.Rand)
			flushPolicy := refraction_networking_prefix.FlushAfterPrefix
			config, err := refraction_networking_transports.NewWithParams(
				transport.Name(),
				&refraction_networking_proto.PrefixTransportParams{
					RandomizeDstPort:  &randomizeDstPort,
					PrefixId:          &prefixID,
					CustomFlushPolicy: &flushPolicy})
			if err != nil {
				return nil, errors.Trace(err)
			}

			refractionDialer.Transport = transport.ID()
			refractionDialer.TransportConfig = config
			refractionDialer.DisableRegistrarOverrides = disableOverrides
			refractionDialer.DialerWithLaddr = newWriteMergeDialer(
				refractionDialer.DialerWithLaddr, true, 64)

		case protocol.CONJURE_TRANSPORT_DTLS_OSSH:

			transport, ok := refraction_networking_transports.GetTransportByID(
				refraction_networking_proto.TransportType_DTLS)
			if !ok {
				return nil, errors.TraceNew("missing DTLS transport")
			}

			config, err := refraction_networking_transports.NewWithParams(
				transport.Name(),
				&refraction_networking_proto.DTLSTransportParams{
					RandomizeDstPort: &randomizeDstPort})
			if err != nil {
				return nil, errors.Trace(err)
			}

			if conjureConfig.STUNServerAddress == "" {
				return nil, errors.TraceNew("missing STUN server address")
			}
			config.SetParams(
				&refraction_networking_dtls.ClientConfig{
					STUNServer: conjureConfig.STUNServerAddress,
				})

			conjureMetricSTUNServerAddress = conjureConfig.STUNServerAddress

			refractionDialer.Transport = transport.ID()
			refractionDialer.TransportConfig = config
			refractionDialer.DisableRegistrarOverrides = disableOverrides

		default:
			return nil, errors.Tracef("invalid Conjure transport: %s", conjureConfig.Transport)
		}
	}

	// If the dial context is cancelled, use dialManager to interrupt
	// refractionDialer.DialContext. See dialManager comment explaining why
	// refractionDialer.DialContext may block even when the input context is
	// cancelled.
	dialComplete := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-dialComplete:
		}
		select {
		// Prioritize the dialComplete case.
		case <-dialComplete:
			return
		default:
		}
		manager.close()
	}()

	conn, err := refractionDialer.DialContext(ctx, "tcp", address)
	close(dialComplete)

	if err != nil {
		// Call manager.close before updating cache, to synchronously shutdown dials
		// and ensure there are no further concurrent reads/writes to the recorded
		// registration before referencing it.
		manager.close()
	}

	// Cache (or put back) a successful registration. Also put back in the
	// specific error case where the phantom dial was canceled, as the
	// registration may still be valid. This operation implicitly extends the TTL
	// of a reused cached registration; we assume the Conjure station is also
	// extending the TTL by the same amount.
	//
	// Limitation: the cancel case shouldn't extend the TTL.

	if useConjure && (conjureCachedRegistration != nil || conjureRecordRegistrar != nil) {

		isCanceled := (err != nil && ctx.Err() == context.Canceled)

		if err == nil || isCanceled {

			registration := conjureCachedRegistration
			if registration == nil {
				// We assume gotapdance is no longer accessing the Registrar.
				registration = conjureRecordRegistrar.registration
			}

			// conjureRecordRegistrar.registration will be nil if there was no cached
			// registration _and_ registration didn't succeed before a cancel.
			if registration != nil {
				conjureRegistrationCache.put(conjureConfig, registration, isCanceled)

				if conjureConfig.Transport == protocol.CONJURE_TRANSPORT_PREFIX_OSSH {

					// Record the selected prefix name after registration, as
					// the registrar may have overridden the client selection.
					conjureMetricPrefix = registration.Transport.Name()
				}
			}

		} else if conjureCachedRegistration != nil {

			conjureConfig.Logger.WithTraceFields(
				common.LogFields{
					"diagnosticID": conjureConfig.DiagnosticID,
					"reason":       "phantom dial failed",
				}).Info(
				"drop cached registration")
		}
	}

	if err != nil {
		return nil, errors.Trace(err)
	}

	manager.startUsingRunCtx()

	refractionConn := &refractionConn{
		Conn:    conn,
		manager: manager,
	}

	if useConjure {
		// Retain these values for logging metrics.
		refractionConn.isConjure = true
		refractionConn.conjureMetricCached = conjureMetricCached
		refractionConn.conjureMetricDelay = conjureMetricDelay
		refractionConn.conjureMetricTransport = conjureMetricTransport
		refractionConn.conjureMetricPrefix = conjureMetricPrefix
		refractionConn.conjureMetricSTUNServerAddress = conjureMetricSTUNServerAddress
	}

	return refractionConn, nil
}

func DeleteCachedConjureRegistration(config *ConjureConfig) {
	conjureRegistrationCache.delete(config)
}

type registrationCache struct {
	mutex sync.Mutex
	TTL   time.Duration
	cache *lrucache.Cache
}

func newRegistrationCache() *registrationCache {
	return &registrationCache{
		cache: lrucache.NewWithLRU(
			lrucache.NoExpiration,
			1*time.Minute,
			REGISTRATION_CACHE_MAX_ENTRIES),
	}
}

func (c *registrationCache) put(
	config *ConjureConfig,
	registration *refraction_networking_client.ConjureReg,
	isCanceled bool) {

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Clear the entire cache if the configured TTL changes to avoid retaining
	// items for too long. This is expected to be an infrequent event. The
	// go-cache-lru API does not offer a mechanism to inspect and adjust the TTL
	// of all existing items.
	if c.TTL != config.RegistrationCacheTTL {
		c.cache.Flush()
		c.TTL = config.RegistrationCacheTTL
	}

	// Drop the cached registration if another entry is found under the same key.
	// Since the dial pops its entry out of the cache, finding an existing entry
	// implies that another tunnel establishment candidate with the same key has
	// successfully registered and connected (or canceled) in the meantime.
	// Prefer that newer cached registration.
	//
	// For Psiphon, one scenario resulting in this condition is that the first
	// dial to a given server, using a cached registration, is delayed long
	// enough that a new candidate for the same server has been started and
	// outpaced the first candidate.
	_, found := c.cache.Get(config.RegistrationCacheKey)
	if found {
		config.Logger.WithTraceFields(
			common.LogFields{
				"diagnosticID": config.DiagnosticID,
				"reason":       "existing entry found",
			}).Info(
			"drop cached registration")
		return
	}

	reason := "connected"
	if isCanceled {
		reason = "canceled"
	}

	config.Logger.WithTraceFields(
		common.LogFields{
			"diagnosticID": config.DiagnosticID,
			"cacheSize":    c.cache.ItemCount(),
			"reason":       reason,
		}).Info(
		"put cached registration")

	c.cache.Set(
		config.RegistrationCacheKey,
		registration,
		c.TTL)
}

func (c *registrationCache) pop(
	config *ConjureConfig) *refraction_networking_client.ConjureReg {

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// See TTL/Flush comment in put.
	if c.TTL != config.RegistrationCacheTTL {
		c.cache.Flush()
		c.TTL = config.RegistrationCacheTTL
	}

	entry, found := c.cache.Get(config.RegistrationCacheKey)

	config.Logger.WithTraceFields(
		common.LogFields{
			"diagnosticID": config.DiagnosticID,
			"cacheSize":    c.cache.ItemCount(),
			"found":        found,
		}).Info(
		"pop cached registration")

	if found {
		c.cache.Delete(config.RegistrationCacheKey)
		return entry.(*refraction_networking_client.ConjureReg)
	}

	return nil
}

func (c *registrationCache) delete(config *ConjureConfig) {

	c.mutex.Lock()
	defer c.mutex.Unlock()

	_, found := c.cache.Get(config.RegistrationCacheKey)

	config.Logger.WithTraceFields(
		common.LogFields{
			"diagnosticID": config.DiagnosticID,
			"found":        found,
		}).Info(
		"delete cached registration")

	if found {
		c.cache.Delete(config.RegistrationCacheKey)
	}
}

var conjureRegistrationCache = newRegistrationCache()

type cachedRegistrar struct {
	registration *refraction_networking_client.ConjureReg
}

func (r *cachedRegistrar) Register(
	_ *refraction_networking_client.ConjureSession,
	_ context.Context) (*refraction_networking_client.ConjureReg, error) {

	return r.registration, nil
}

func (r *cachedRegistrar) PrepareRegKeys(_ [32]byte, _ []byte) error {
	return nil
}

type recordRegistrar struct {
	registrar    refraction_networking_client.Registrar
	registration *refraction_networking_client.ConjureReg
}

func (r *recordRegistrar) Register(
	session *refraction_networking_client.ConjureSession,
	ctx context.Context) (*refraction_networking_client.ConjureReg, error) {

	registration, err := r.registrar.Register(session, ctx)
	if err != nil {
		return nil, errors.Trace(err)
	}
	r.registration = registration
	return registration, nil
}

func (r *recordRegistrar) PrepareRegKeys(_ [32]byte, _ []byte) error {
	return nil
}

// writeMergeConn merges Conjure transport and subsequent OSSH writes in order
// to avoid fixed-sized first or second TCP packets always containing exactly
// the 32-byte or 64-byte HMAC tag.
//
// The Conjure Prefix transport will first write a prefix. writeMergeConn
// assumes the FlushAfterPrefix policy is used, so the first write call for
// that transport will be exactly the arbitrary sized prefix. The second
// write call will be the HMAC tag. Pass the first write through to the
// underlying conn, and then expect the HMAC tag on the second write, and
// handle as follows.
//
// The Conjure Min transport first calls write with an HMAC tag. Buffer this
// value and await the following initial OSSH write, and prepend the buffered
// HMAC tag to the random OSSH data. The first write by OSSH will be a
// variable length multi-packet-sized sequence of random bytes.
type writeMergeConn struct {
	net.Conn
	tagSize int

	mutex  sync.Mutex
	state  int
	buffer []byte
	err    error
}

const (
	stateWriteMergeAwaitingPrefix = iota
	stateWriteMergeAwaitingTag
	stateWriteMergeBufferedTag
	stateWriteMergeFinishedMerging
	stateWriteMergeFailed
)

func newWriteMergeConn(conn net.Conn, hasPrefix bool, tagSize int) *writeMergeConn {
	c := &writeMergeConn{
		Conn:    conn,
		tagSize: tagSize,
	}
	if hasPrefix {
		c.state = stateWriteMergeAwaitingPrefix
	} else {
		c.state = stateWriteMergeAwaitingTag
	}
	return c
}

func (conn *writeMergeConn) Write(p []byte) (int, error) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	switch conn.state {

	case stateWriteMergeAwaitingPrefix:
		conn.state = stateWriteMergeAwaitingTag
		return conn.Conn.Write(p)

	case stateWriteMergeAwaitingTag:
		if len(p) != conn.tagSize {
			conn.state = stateWriteMergeFailed
			conn.err = errors.Tracef("unexpected tag write size: %d", len(p))
			return 0, conn.err
		}
		conn.buffer = make([]byte, conn.tagSize)
		copy(conn.buffer, p)
		conn.state = stateWriteMergeBufferedTag
		return conn.tagSize, nil

	case stateWriteMergeBufferedTag:
		conn.buffer = append(conn.buffer, p...)
		n, err := conn.Conn.Write(conn.buffer)
		if err != nil {
			conn.state = stateWriteMergeFailed
			conn.err = errors.Trace(err)
		} else {
			conn.state = stateWriteMergeFinishedMerging
			conn.buffer = nil
		}
		n -= conn.tagSize
		if n < 0 {
			n = 0
		}
		// Do not wrap Conn.Write errors
		return n, err

	case stateWriteMergeFinishedMerging:
		return conn.Conn.Write(p)

	case stateWriteMergeFailed:
		// Return the original error that caused the failure
		return 0, conn.err

	default:
		return 0, errors.TraceNew("unexpected state")
	}
}

func newWriteMergeDialer(dialer Dialer, hasPrefix bool, tagSize int) Dialer {
	return func(ctx context.Context, network, laddr, raddr string) (net.Conn, error) {
		conn, err := dialer(ctx, network, laddr, raddr)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return newWriteMergeConn(conn, hasPrefix, tagSize), nil
	}
}

// dialManager tracks all dials performed by and dialed conns used by a
// refraction_networking_client conn. dialManager.close interrupts/closes
// all pending dials and established conns immediately. This ensures that
// blocking calls within refraction_networking_client, such as tls.Handhake,
// are interrupted:
// E.g., https://github.com/refraction-networking/gotapdance/blob/4d84655dad2e242b0af0459c31f687b12085dcca/tapdance/conn_raw.go#L307
// (...preceeding SetDeadline is insufficient for immediate cancellation.)
//
// This remains an issue with the Conjure Decoy Registrar:
// https://github.com/refraction-networking/conjure/blob/d9d58260cc7017ab0c64b120579b123a5b2d1c96/pkg/registrars/decoy-registrar/decoy-registrar.go#L208
type dialManager struct {
	ctxMutex       sync.Mutex
	useRunCtx      bool
	initialDialCtx context.Context
	runCtx         context.Context
	stopRunning    context.CancelFunc

	conns *common.Conns
}

func newDialManager() *dialManager {
	runCtx, stopRunning := context.WithCancel(context.Background())
	return &dialManager{
		runCtx:      runCtx,
		stopRunning: stopRunning,
		conns:       common.NewConns(),
	}
}

func (manager *dialManager) makeManagedDialer(dialer Dialer) Dialer {

	return func(ctx context.Context, network, laddr, raddr string) (net.Conn, error) {
		return manager.dialWithDialer(dialer, ctx, network, laddr, raddr)
	}
}

func (manager *dialManager) dialWithDialer(
	dialer Dialer,
	ctx context.Context,
	network string,
	laddr string,
	raddr string) (net.Conn, error) {

	// The context for this dial is either:
	// - ctx, during the initial refraction_networking_client.DialContext, when
	//   this is Psiphon tunnel establishment.
	// - manager.runCtx after the initial refraction_networking_client.Dial
	//   completes, in which case this is a TapDance protocol reconnection that
	//   occurs periodically for already established tunnels.

	manager.ctxMutex.Lock()
	if manager.useRunCtx {

		// Preserve the random timeout configured by the TapDance client:
		// https://github.com/refraction-networking/gotapdance/blob/4d84655dad2e242b0af0459c31f687b12085dcca/tapdance/conn_raw.go#L263
		deadline, ok := ctx.Deadline()
		if !ok {
			return nil, errors.Tracef("unexpected nil deadline")
		}
		var cancelFunc context.CancelFunc
		ctx, cancelFunc = context.WithDeadline(manager.runCtx, deadline)
		defer cancelFunc()
	}
	manager.ctxMutex.Unlock()

	conn, err := dialer(ctx, network, laddr, raddr)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Fail immediately if CloseWrite isn't available in the underlying dialed
	// conn. The equivalent check in managedConn.CloseWrite isn't fatal and
	// TapDance will run in a degraded state.
	// Limitation: if the underlying conn _also_ passes through CloseWrite, this
	// check may be insufficient.
	if _, ok := conn.(common.CloseWriter); network == "tcp" && !ok {
		return nil, errors.TraceNew("underlying conn is not a CloseWriter")
	}

	conn = &managedConn{
		Conn:    conn,
		manager: manager,
	}

	if !manager.conns.Add(conn) {
		conn.Close()
		return nil, errors.TraceNew("already closed")
	}

	return conn, nil
}

func (manager *dialManager) startUsingRunCtx() {
	manager.ctxMutex.Lock()
	manager.initialDialCtx = nil
	manager.useRunCtx = true
	manager.ctxMutex.Unlock()
}

func (manager *dialManager) close() {
	manager.conns.CloseAll()
	manager.stopRunning()
}

type managedConn struct {
	net.Conn
	manager *dialManager
}

type fileConn interface {
	File() (*os.File, error)
}

// File exposes the net.UDPConn.File() functionality required by the Conjure
// DTLS transport.
func (conn *managedConn) File() (*os.File, error) {
	if f, ok := conn.Conn.(fileConn); ok {
		return f.File()
	}
	return nil, errors.TraceNew("underlying conn is not a fileConn")
}

// CloseWrite exposes the net.TCPConn.CloseWrite() functionality
// required by TapDance.
func (conn *managedConn) CloseWrite() error {
	if closeWriter, ok := conn.Conn.(common.CloseWriter); ok {
		return closeWriter.CloseWrite()
	}
	return errors.TraceNew("underlying conn is not a CloseWriter")
}

func (conn *managedConn) Close() error {
	// Remove must be invoked asynchronously, as this Close may be called by
	// conns.CloseAll, leading to a reentrant lock situation.
	go conn.manager.conns.Remove(conn)
	return conn.Conn.Close()
}

type refractionConn struct {
	net.Conn
	manager  *dialManager
	isClosed int32

	isConjure                      bool
	conjureMetricCached            bool
	conjureMetricDelay             time.Duration
	conjureMetricTransport         string
	conjureMetricPrefix            string
	conjureMetricSTUNServerAddress string
}

func (conn *refractionConn) Write(p []byte) (int, error) {
	n, err := conn.Conn.Write(p)

	// For the DTLS transport, underlying SCTP conn writes may fail
	// with "stream closed" -- which indicates a permanent failure of the
	// transport -- without closing the conn. Explicitly close the conn on
	// this error, which will trigger Psiphon to reconnect faster via
	// IsClosed checks on port forward failures.
	//
	// The close is invoked asynchronously to avoid possible deadlocks due to
	// a hypothetical panic in the Close call: for a port forward, the unwind
	// will invoke a deferred ssh.channel.Close which reenters Write;
	// meanwhile, the underlying ssh.channel.writePacket acquires a
	// ssh.channel.writeMu lock but does not defer the unlock.

	if std_errors.Is(err, sctp.ErrStreamClosed) {
		go func() {
			_ = conn.Close()
		}()
	}
	return n, err
}

func (conn *refractionConn) Close() error {
	conn.manager.close()
	err := conn.Conn.Close()
	atomic.StoreInt32(&conn.isClosed, 1)
	return err
}

func (conn *refractionConn) IsClosed() bool {
	return atomic.LoadInt32(&conn.isClosed) == 1
}

// GetMetrics implements the common.MetricsSource interface.
func (conn *refractionConn) GetMetrics() common.LogFields {
	logFields := make(common.LogFields)
	if conn.isConjure {

		cached := "0"
		if conn.conjureMetricCached {
			cached = "1"
		}
		logFields["conjure_cached"] = cached

		if conn.conjureMetricDelay != -1 {
			logFields["conjure_delay"] = fmt.Sprintf("%d", conn.conjureMetricDelay/time.Millisecond)
		}

		logFields["conjure_transport"] = conn.conjureMetricTransport

		if conn.conjureMetricPrefix != "" {
			logFields["conjure_prefix"] = conn.conjureMetricPrefix
		}

		if conn.conjureMetricSTUNServerAddress != "" {
			logFields["conjure_stun"] = conn.conjureMetricSTUNServerAddress
		}

		host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err == nil {
			network := "IPv4"
			if IP := net.ParseIP(host); IP != nil && IP.To4() == nil {
				network = "IPv6"
			}
			logFields["conjure_network"] = network
			logFields["conjure_port_number"] = port
		}
	}

	return logFields
}

var initRefractionNetworkingOnce sync.Once

func initRefractionNetworking(emitLogs bool, dataDirectory string) error {

	var initErr error
	initRefractionNetworkingOnce.Do(func() {

		if !emitLogs {
			refraction_networking_client.Logger().Out = ioutil.Discard
		} else {
			refraction_networking_client.Logger().Out = os.Stdout
		}

		assetsDir := filepath.Join(dataDirectory, "refraction-networking")

		err := os.MkdirAll(assetsDir, 0700)
		if err != nil {
			initErr = errors.Trace(err)
			return
		}

		clientConfFileName := filepath.Join(assetsDir, "ClientConf")
		_, err = os.Stat(clientConfFileName)
		if err != nil && os.IsNotExist(err) {
			err = ioutil.WriteFile(clientConfFileName, getEmbeddedClientConf(), 0644)
		}
		if err != nil {
			initErr = errors.Trace(err)
			return
		}

		refraction_networking_assets.AssetsSetDir(assetsDir)

		// TapDance now uses a distinct Assets/ClientConf,
		// refraction_networking_client.Assets. Do not configure the TapDance
		// ClientConf to use the same configuration as Conjure, as the
		// Conjure ClientConf may contain decoys that are appropriate for
		// registration load but not full TapDance tunnel load.
	})

	return initErr
}
