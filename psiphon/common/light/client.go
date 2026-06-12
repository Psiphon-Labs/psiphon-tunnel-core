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
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/obfuscator"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

const (
	clientInactivityTimeout = 5 * time.Minute
)

// TCPDialer is a callback that dials a TCP connection. The dialer allows for
// integrating Psiphon features including BindToDevice support, optional
// custom DNS resolver, and BPF.
type TCPDialer func(
	ctx context.Context, addr string) (net.Conn, error)

// TLSDialer is callback that dials a TLS connection over the provided
// underlying TCP connection. The dialer allows for integrating Psiphon
// features including utls, passthrough, pin verification, session caching,
// and replay.
type TLSDialer func(
	ctx context.Context,
	underlyingConn net.Conn,
	tlsProfile string,
	randomizedTLSProfileSeed *prng.Seed,
	sni string,
	fragmentClientHello bool,
	tlsPadding int,
	passthroughMessage []byte,
	verifyPin string,
	verifyServerName string) (net.Conn, error)

// ClientConfig specifies the configuration of a light proxy client.
type ClientConfig struct {
	Logger    common.Logger
	TCPDialer TCPDialer
	TLSDialer TLSDialer

	SponsorID         string
	ClientPlatform    string
	ClientBuildRev    string
	DeviceRegion      string
	SessionID         string
	ProxyEntryTracker int64

	ProxyEntry []byte
}

// Client is a light proxy client which supports multiple concurrent dials.
type Client struct {
	config            *ClientConfig
	sponsorID         []byte
	clientPlatform    uint8
	clientBuildRev    []byte
	sessionID         []byte
	proxyEntry        *ProxyEntry
	proxyEntryTracker string
	proxyID           string
	obfuscationKey    string
	verifyPin         string
	connectionNumber  atomic.Int64
	dialIPv4Count     atomic.Int64
	dialIPv6Count     atomic.Int64
	dialFailedCount   atomic.Int64
}

type ClientMetrics struct {
	ProxyID           string
	ProxyEntryTracker int64
	DialIPv4Count     int64
	HasIPv6           bool
	DialIPv6Count     int64
	DialFailedCount   int64
}

// NewClient initializes a Client.
func NewClient(config *ClientConfig) (*Client, error) {

	if config == nil ||
		config.Logger == nil ||
		config.TCPDialer == nil ||
		config.TLSDialer == nil {
		return nil, errors.TraceNew("invalid config")
	}

	// Perform one-time checks and conversions for all parameters that are
	// common across dials.

	sponsorID, err := hex.DecodeString(config.SponsorID)
	if err != nil {
		return nil, errors.Trace(err)
	}

	clientPlatform := encodeClientPlatform(config.ClientPlatform)

	// Truncate odd length client build revs to enable conversion to binary.
	// This is a fail safe: the build script should set a sufficiently long,
	// even-length build rev.
	hexClientBuildRev := config.ClientBuildRev
	if len(hexClientBuildRev)%2 == 1 {
		hexClientBuildRev = hexClientBuildRev[:len(hexClientBuildRev)-1]
	}

	clientBuildRev, err := hex.DecodeString(hexClientBuildRev)
	if err != nil {
		return nil, errors.Trace(err)
	}

	sessionID, err := hex.DecodeString(config.SessionID)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if len(config.ProxyEntry) == 0 {
		return nil, errors.TraceNew("missing proxy entry")
	}

	proxyEntryTracker := fmt.Sprintf("%016x", config.ProxyEntryTracker)

	proxyEntry, err := DecodeAndValidateProxyEntry(config.ProxyEntry)
	if err != nil {
		return nil, errors.Trace(err)
	}

	obfuscationKey := hex.EncodeToString(proxyEntry.ObfuscationKey)
	verifyPin := base64.StdEncoding.EncodeToString(proxyEntry.VerifyPin)
	proxyID := makeProxyID(proxyEntry.DialAddressIPv4, obfuscationKey)

	client := &Client{
		config:            config,
		sponsorID:         sponsorID,
		clientPlatform:    clientPlatform,
		clientBuildRev:    clientBuildRev,
		sessionID:         sessionID,
		proxyEntryTracker: proxyEntryTracker,
		proxyEntry:        proxyEntry,
		proxyID:           proxyID,
		obfuscationKey:    obfuscationKey,
		verifyPin:         verifyPin,
	}

	return client, nil
}

// GetRecommendedSNI returns the recommended SNI included in the proxy entry,
// if any.
func (client *Client) GetRecommendedSNI() string {
	return client.proxyEntry.RecommendedSNI
}

// GetRecommendedSNIRegex returns the recommended SNI regex included in the
// proxy entry, if any.
func (client *Client) GetRecommendedSNIRegex() string {
	return client.proxyEntry.RecommendedSNIRegex
}

// GetRecommendedSNIProbability returns the recommended SNI probability
// included in the proxy entry.
func (client *Client) GetRecommendedSNIProbability() float64 {
	return client.proxyEntry.RecommendedSNIProbability
}

// GetRecommendedTLSProfile returns the recommended TLS profile included in
// the proxy entry, if any.
func (client *Client) GetRecommendedTLSProfile() string {
	return client.proxyEntry.RecommendedTLSProfile
}

// GetRecommendedTLSProfileProbability returns the recommended TLS profile
// probability included in the proxy entry.
func (client *Client) GetRecommendedTLSProfileProbability() float64 {
	return client.proxyEntry.RecommendedTLSProfileProbability
}

// GetRecommendedFragmentClientHelloProbability returns the recommended
// FragmentClientHello probability included in the proxy entry.
func (client *Client) GetRecommendedFragmentClientHelloProbability() float64 {
	return client.proxyEntry.RecommendedFragmentClientHelloProbability
}

// GetRecommendedTLSPaddingProbability returns the recommended TLS padding
// probability included in the proxy entry.
func (client *Client) GetRecommendedTLSPaddingProbability() float64 {
	return client.proxyEntry.RecommendedTLSPaddingProbability
}

// GetRecommendedMinTLSPadding returns the recommended minimum TLS padding
// included in the proxy entry.
func (client *Client) GetRecommendedMinTLSPadding() int {
	return client.proxyEntry.RecommendedMinTLSPadding
}

// GetRecommendedMaxTLSPadding returns the recommended maximum TLS padding
// included in the proxy entry.
func (client *Client) GetRecommendedMaxTLSPadding() int {
	return client.proxyEntry.RecommendedMaxTLSPadding
}

func (client *Client) GetMetrics() *ClientMetrics {
	return &ClientMetrics{
		ProxyID:           client.proxyID,
		ProxyEntryTracker: client.config.ProxyEntryTracker,
		DialIPv4Count:     client.dialIPv4Count.Load(),
		HasIPv6:           client.proxyEntry.DialAddressIPv6 != "",
		DialIPv6Count:     client.dialIPv6Count.Load(),
		DialFailedCount:   client.dialFailedCount.Load(),
	}
}

// Dial connects to the specified destination.
//
// The light proxy protocol requires the client to write first, and the light
// header is prepended to the client's first write.
func (client *Client) Dial(
	ctx context.Context,
	additionalLogFields common.LogFields,
	networkType string,
	tlsProfile string,
	randomizedTLSProfileSeed *prng.Seed,
	sni string,
	fragmentClientHello bool,
	tlsPadding int,
	destinationAddress string) (retConn *ClientConn, retErr error) {

	// Start at 1 to distinguish from the zero value the proxy will record if
	// the header is not delivered.
	connectionNum := client.connectionNumber.Add(1)

	passthroughMessage, err := obfuscator.MakeTLSPassthroughMessage(
		true, client.obfuscationKey)
	if err != nil {
		return nil, errors.Trace(err)
	}

	logFields := common.LogFields{
		"proxyID":           client.proxyID,
		"proxyEntryTracker": client.proxyEntryTracker,
		"connectionNum":     connectionNum,
		"tlsProfile":        tlsProfile,
		"SNI":               sni,
		"hasIPv6":           client.proxyEntry.DialAddressIPv6 != "",
	}
	logFields.Add(additionalLogFields)

	// Log once per connection. If the dial fails, log accumulated fields
	// here. Otherwise, log on Close.
	defer func() {
		if retErr != nil && ctx.Err() != context.Canceled {
			client.dialFailedCount.Add(1)
			logFields["error"] = retErr.Error()
			client.config.Logger.WithTraceFields(
				logFields).Warning("light proxy dial failed")
		}
	}()

	start := time.Now()

	var tcpConn net.Conn
	isIPv6 := false

	if client.proxyEntry.DialAddressIPv6 == "" {
		tcpConn, err = client.config.TCPDialer(ctx, client.proxyEntry.DialAddressIPv4)
		if err != nil {
			return nil, errors.Trace(err)
		}
	} else {

		// Dial IPv4 and IPv6 concurrently and use the first to connect.
		//
		// Currently, there's no check that the client has an IPv6 interface as
		// that case is expected to simply fail fast and not generate log
		// noise. An interface check is possible, similar to
		// resolver.hasRoutableIPv6Interface and/or inproxy.pionNetwork.Interfaces,
		// although that may be more expensive than just dialing.

		tcpCtx, tcpCancel := context.WithCancel(ctx)
		defer tcpCancel()
		type tcpResult struct {
			conn   net.Conn
			isIPv6 bool
			err    error
		}
		tcpChan := make(chan tcpResult, 2)
		tcpDial := func(addr string, isIPv6 bool) {
			conn, err := client.config.TCPDialer(tcpCtx, addr)
			tcpChan <- tcpResult{conn, isIPv6, errors.Trace(err)}
		}
		go tcpDial(client.proxyEntry.DialAddressIPv4, false)
		go tcpDial(client.proxyEntry.DialAddressIPv6, true)
		result := <-tcpChan
		if result.err == nil {
			tcpConn = result.conn
			isIPv6 = result.isIPv6
			tcpCancel()
			result = <-tcpChan
			if result.err == nil {
				_ = result.conn.Close()
			}
		} else {
			result = <-tcpChan
			if result.err != nil {
				return nil, errors.Trace(result.err)
			}
			tcpConn = result.conn
			isIPv6 = result.isIPv6
			tcpCancel()
		}
	}
	defer func() {
		if retErr != nil {
			_ = tcpConn.Close()
		}
	}()

	TCPDuration := time.Since(start)

	logFields["TCPDuration"] = TCPDuration.String()
	logFields["isIPv6"] = isIPv6

	// Wrapping here counts outer TLS handshake bytes.
	bytesCounter := &bytesCounter{}
	activityConn, err := common.NewActivityMonitoredConn(
		tcpConn, clientInactivityTimeout, false, nil, bytesCounter)
	if err != nil {
		return nil, errors.Trace(err)
	}

	start = time.Now()
	tlsConn, err := client.config.TLSDialer(
		ctx,
		activityConn,
		tlsProfile,
		randomizedTLSProfileSeed,
		sni,
		fragmentClientHello,
		tlsPadding,
		passthroughMessage,
		client.verifyPin,
		client.proxyEntry.VerifyServerName)
	if err != nil {
		return nil, errors.Trace(err)
	}
	TLSDuration := time.Since(start)

	logFields["TLSDuration"] = TLSDuration.String()
	// TODO: log tlsConn.ConnectionState().DidResume

	header, err := newLightHeader(
		client.sponsorID,
		client.clientPlatform,
		client.clientBuildRev,
		client.config.DeviceRegion,
		client.sessionID,
		client.config.ProxyEntryTracker,
		encodeNetworkType(networkType),
		connectionNum,
		destinationAddress,
		encodeTLSProfile(tlsProfile),
		int64(TCPDuration),
		int64(TLSDuration))
	if err != nil {
		return nil, errors.Trace(err)
	}

	lightConn := newLightConn(tlsConn, header)

	clientConn := &ClientConn{
		logFields:     logFields,
		lightConn:     lightConn,
		activityConn:  activityConn,
		client:        client,
		connectionNum: connectionNum,
		bytesCounter:  bytesCounter,
	}

	if isIPv6 {
		client.dialIPv6Count.Add(1)
	} else {
		client.dialIPv4Count.Add(1)
	}

	return clientConn, nil
}

type ClientConn struct {
	*lightConn
	logFields     common.LogFields
	activityConn  *common.ActivityMonitoredConn
	client        *Client
	connectionNum int64
	bytesCounter  *bytesCounter

	closeOnce sync.Once
	closeErr  error
}

func (conn *ClientConn) Close() error {
	conn.closeOnce.Do(func() {
		conn.closeErr = errors.Trace(conn.lightConn.Close())

		conn.logFields["bytesRead"] = conn.bytesCounter.bytesRead.Load()
		conn.logFields["bytesWritten"] = conn.bytesCounter.bytesWritten.Load()
		conn.logFields["duration"] = conn.activityConn.GetActiveDuration().String()

		conn.client.config.Logger.WithTraceFields(
			conn.logFields).Info("light proxy connection")
	})
	return conn.closeErr
}
