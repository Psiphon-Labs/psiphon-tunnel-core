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
	"github.com/fxamacker/cbor/v2"
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

	clientBuildRev, err := hex.DecodeString(config.ClientBuildRev)
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

	var signedProxyEntry SignedProxyEntry
	err = cbor.Unmarshal(config.ProxyEntry, &signedProxyEntry)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// There is currently no signature. See SignedProxyEntry comment.
	proxyEntry := &signedProxyEntry.ProxyEntry

	if proxyEntry.Protocol != LIGHT_PROTOCOL_TLS {
		return nil, errors.TraceNew("unsupported proxy protocol")
	}

	if len(proxyEntry.ObfuscationKey) == 0 {
		return nil, errors.TraceNew("missing obfuscation key")
	}
	obfuscationKey := hex.EncodeToString(proxyEntry.ObfuscationKey)

	if len(proxyEntry.VerifyPin) == 0 {
		return nil, errors.TraceNew("missing TLS verify pin")
	}
	verifyPin := base64.StdEncoding.EncodeToString(proxyEntry.VerifyPin)

	proxyID := makeProxyID(proxyEntry.DialAddress, obfuscationKey)

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

// Dial connects to the specified destination.
//
// The light proxy protocol requires the client to write first, and the light
// header is prepended to the client's first write.
func (client *Client) Dial(
	ctx context.Context,
	networkType string,
	tlsProfile string,
	randomizedTLSProfileSeed *prng.Seed,
	sni string,
	destinationAddress string) (retConn *ClientConn, retErr error) {

	passthroughMessage, err := obfuscator.MakeTLSPassthroughMessage(
		true, client.obfuscationKey)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Start at 1 to distinguish from the zero value the proxy will record if
	// the header is not delivered.
	connectionNum := client.connectionNumber.Add(1)

	client.config.Logger.WithTraceFields(common.LogFields{
		"proxyID":           client.proxyID,
		"proxyEntryTracker": client.proxyEntryTracker,
		"connectionNum":     connectionNum,
		"tlsProfile":        tlsProfile,
		"sni":               sni,
	}).Info("dialing")

	start := time.Now()
	tcpConn, err := client.config.TCPDialer(ctx, client.proxyEntry.DialAddress)
	if err != nil {
		return nil, errors.Trace(err)
	}
	defer func() {
		if retErr != nil {
			_ = tcpConn.Close()
		}
	}()
	TCPDuration := time.Since(start)

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
		passthroughMessage,
		client.verifyPin,
		client.proxyEntry.VerifyServerName)
	if err != nil {
		return nil, errors.Trace(err)
	}
	TLSDuration := time.Since(start)

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

	client.config.Logger.WithTraceFields(common.LogFields{
		"proxyID":           client.proxyID,
		"proxyEntryTracker": client.proxyEntryTracker,
		"connectionNum":     connectionNum,
		"tlsProfile":        tlsProfile,
		"sni":               sni,
		"TCPDuration":       TCPDuration.String(),
		"TLSDuration":       TLSDuration.String(),
	}).Info("connected")

	lightConn := newLightConn(tlsConn, header)

	clientConn := &ClientConn{
		lightConn:     lightConn,
		activityConn:  activityConn,
		client:        client,
		connectionNum: connectionNum,
		bytesCounter:  bytesCounter,
	}

	return clientConn, nil
}

type ClientConn struct {
	*lightConn
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
		conn.client.config.Logger.WithTraceFields(
			common.LogFields{
				"proxyID":       conn.client.proxyID,
				"connectionNum": conn.connectionNum,
				"bytesRead":     conn.bytesCounter.bytesRead.Load(),
				"bytesWritten":  conn.bytesCounter.bytesWritten.Load(),
				"duration":      conn.activityConn.GetActiveDuration().String(),
			}).Info("closed")
	})
	return conn.closeErr
}
