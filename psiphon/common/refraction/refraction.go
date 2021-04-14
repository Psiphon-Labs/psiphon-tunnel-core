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
	"crypto/sha256"
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
	refraction_networking_proto "github.com/refraction-networking/gotapdance/protobuf"
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
	dialer common.NetDialer,
	address string) (net.Conn, error) {

	return dial(
		ctx,
		emitLogs,
		dataDirectory,
		dialer,
		address,
		nil)
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
	dialer common.NetDialer,
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
	dialer common.NetDialer,
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
		TcpDialer:      manager.makeManagedDialer(dialer.DialContext),
		UseProxyHeader: true,
	}

	conjureCached := false
	conjureDelay := time.Duration(0)

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

		conjureCachedRegistration = conjureRegistrationCache.pop(
			conjureConfig.RegistrationCacheTTL,
			conjureConfig.RegistrationCacheKey)

		if conjureCachedRegistration != nil {

			refractionDialer.DarkDecoyRegistrar = &cachedRegistrar{
				registration: conjureCachedRegistration,
			}

			conjureCached = true
			conjureDelay = 0 // report no delay

		} else if conjureConfig.APIRegistrarURL != "" {

			if conjureConfig.APIRegistrarHTTPClient == nil {
				// While not a guaranteed check, if the APIRegistrarHTTPClient isn't set
				// then the API registration would certainly be unfronted, resulting in a
				// fingerprintable connection leak.
				return nil, errors.TraceNew("missing APIRegistrarHTTPClient")
			}

			refractionDialer.DarkDecoyRegistrar = &refraction_networking_client.APIRegistrar{
				Endpoint:        conjureConfig.APIRegistrarURL,
				ConnectionDelay: conjureConfig.APIRegistrarDelay,
				MaxRetries:      0,
				Client:          conjureConfig.APIRegistrarHTTPClient,
			}

			conjureDelay = conjureConfig.APIRegistrarDelay

		} else if conjureConfig.DecoyRegistrarDialer != nil {

			refractionDialer.DarkDecoyRegistrar = &refraction_networking_client.DecoyRegistrar{
				TcpDialer: manager.makeManagedDialer(
					conjureConfig.DecoyRegistrarDialer.DialContext),
			}

			refractionDialer.Width = conjureConfig.DecoyRegistrarWidth

			// Limitation: the decoy regsitration delay is not currently exposed in the
			// gotapdance API.
			conjureDelay = -1 // don't report delay

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

		switch conjureConfig.Transport {
		case protocol.CONJURE_TRANSPORT_MIN_OSSH:
			refractionDialer.Transport = refraction_networking_proto.TransportType_Min
			refractionDialer.TcpDialer = newMinTransportDialer(refractionDialer.TcpDialer)
		case protocol.CONJURE_TRANSPORT_OBFS4_OSSH:
			refractionDialer.Transport = refraction_networking_proto.TransportType_Obfs4
		default:
			return nil, errors.Tracef("invalid Conjure transport: %s", conjureConfig.Transport)
		}

		if conjureCachedRegistration != nil {

			// When using a cached registration, patch its TcpDialer to use the custom
			// dialer for this dial. In the non-cached code path, gotapdance will set
			// refractionDialer.TcpDialer into a new registration.
			conjureCachedRegistration.TcpDialer = refractionDialer.TcpDialer
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

	if useConjure &&
		(err == nil || ctx.Err() == context.Canceled) &&
		(conjureCachedRegistration != nil || conjureRecordRegistrar != nil) {

		registration := conjureCachedRegistration
		if registration == nil {
			// We assume gotapdance is no longer accessing the Registrar.
			registration = conjureRecordRegistrar.registration
		}

		// conjureRecordRegistrar.registration will be nil there was no cached
		// registration _and_ registration didn't succeed before a cancel.
		if registration != nil {

			// Do not retain a reference to the custom dialer, as its context will not
			// be valid for future dials using this cached registration. Assumes that
			// gotapdance will no longer reference the TcpDialer now that the
			// connection is established.
			registration.TcpDialer = nil

			conjureRegistrationCache.put(
				conjureConfig.RegistrationCacheTTL,
				conjureConfig.RegistrationCacheKey,
				registration)
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
		refractionConn.conjureCached = conjureCached
		refractionConn.conjureDelay = conjureDelay
		refractionConn.conjureTransport = conjureConfig.Transport
	}

	return refractionConn, nil
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
	TTL time.Duration,
	key string,
	registration *refraction_networking_client.ConjureReg) {

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Clear the entire cache if the configured TTL changes to avoid retaining
	// items for too long. This is expected to be an infrequent event. The
	// go-cache-lru API does not offer a mechanism to inspect and adjust the TTL
	// of all existing items.
	if c.TTL != TTL {
		c.cache.Flush()
		c.TTL = TTL
	}

	c.cache.Set(
		key,
		registration,
		c.TTL)
}

func (c *registrationCache) pop(
	TTL time.Duration,
	key string) *refraction_networking_client.ConjureReg {

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// See TTL/Flush comment in put.
	if c.TTL != TTL {
		c.cache.Flush()
		c.TTL = TTL
	}

	entry, found := c.cache.Get(key)
	if found {
		c.cache.Delete(key)
		return entry.(*refraction_networking_client.ConjureReg)
	}

	return nil
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

// minTransportConn buffers the first 32-byte random HMAC write performed by
// Conjure TransportType_Min, and prepends it to the subsequent first write
// made by OSSH. The purpose is to avoid a distinct fingerprint consisting of
// the initial TCP data packet always containing exactly 32 bytes of payload.
// The first write by OSSH will be a variable length multi-packet-sized
// sequence of random bytes.
type minTransportConn struct {
	net.Conn

	mutex  sync.Mutex
	state  int
	buffer []byte
	err    error
}

const (
	stateMinTransportInit = iota
	stateMinTransportBufferedHMAC
	stateMinTransportWroteHMAC
	stateMinTransportFailed
)

func newMinTransportConn(conn net.Conn) *minTransportConn {
	return &minTransportConn{
		Conn:  conn,
		state: stateMinTransportInit,
	}
}

func (conn *minTransportConn) Write(p []byte) (int, error) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	switch conn.state {
	case stateMinTransportInit:
		if len(p) != sha256.Size {
			conn.state = stateMinTransportFailed
			conn.err = errors.TraceNew("unexpected HMAC write size")
			return 0, conn.err
		}
		conn.buffer = make([]byte, sha256.Size)
		copy(conn.buffer, p)
		conn.state = stateMinTransportBufferedHMAC
		return sha256.Size, nil
	case stateMinTransportBufferedHMAC:
		conn.buffer = append(conn.buffer, p...)
		n, err := conn.Conn.Write(conn.buffer)
		if n < sha256.Size {
			conn.state = stateMinTransportFailed
			conn.err = errors.TraceNew("failed to write HMAC")
			if err == nil {
				// As Write must return an error when failing to write the entire buffer,
				// we don't expect to hit this case.
				err = conn.err
			}
		} else {
			conn.state = stateMinTransportWroteHMAC
		}
		n -= sha256.Size
		// Do not wrap Conn.Write errors, and do not return conn.err here.
		return n, err
	case stateMinTransportWroteHMAC:
		return conn.Conn.Write(p)
	case stateMinTransportFailed:
		return 0, conn.err
	default:
		return 0, errors.TraceNew("unexpected state")
	}
}

func newMinTransportDialer(dialer common.Dialer) common.Dialer {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dialer(ctx, network, address)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return newMinTransportConn(conn), nil
	}
}

// dialManager tracks all dials performed by and dialed conns used by a
// refraction_networking_client conn. dialManager.close interrupts/closes
// all pending dials and established conns immediately. This ensures that
// blocking calls within refraction_networking_client, such as tls.Handhake,
// are interrupted:
// E.g., https://github.com/refraction-networking/gotapdance/blob/4d84655dad2e242b0af0459c31f687b12085dcca/tapdance/conn_raw.go#L307
// (...preceeding SetDeadline is insufficient for immediate cancellation.)
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

func (manager *dialManager) makeManagedDialer(dialer common.Dialer) common.Dialer {

	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return manager.dialWithDialer(dialer, ctx, network, address)
	}
}

func (manager *dialManager) dialWithDialer(
	dialer common.Dialer,
	ctx context.Context,
	network string,
	address string) (net.Conn, error) {

	if network != "tcp" {
		return nil, errors.Tracef("unsupported network: %s", network)
	}

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

	conn, err := dialer(ctx, network, address)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Fail immediately if CloseWrite isn't available in the underlying dialed
	// conn. The equivalent check in managedConn.CloseWrite isn't fatal and
	// TapDance will run in a degraded state.
	// Limitation: if the underlying conn _also_ passes through CloseWrite, this
	// check may be insufficient.
	if _, ok := conn.(common.CloseWriter); !ok {
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

	isConjure        bool
	conjureCached    bool
	conjureDelay     time.Duration
	conjureTransport string
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
		if conn.conjureCached {
			cached = "1"
		}
		logFields["conjure_cached"] = cached

		if conn.conjureDelay != -1 {
			logFields["conjure_delay"] = fmt.Sprintf("%d", conn.conjureDelay/time.Millisecond)
		}

		logFields["conjure_transport"] = conn.conjureTransport
	}
	return logFields
}

var initRefractionNetworkingOnce sync.Once

func initRefractionNetworking(emitLogs bool, dataDirectory string) error {

	var initErr error
	initRefractionNetworkingOnce.Do(func() {

		if !emitLogs {
			refraction_networking_client.Logger().Out = ioutil.Discard
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

		refraction_networking_client.AssetsSetDir(assetsDir)
	})

	return initErr
}
