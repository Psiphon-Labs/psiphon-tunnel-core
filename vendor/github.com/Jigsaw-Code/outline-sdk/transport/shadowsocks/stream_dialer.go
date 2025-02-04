// Copyright 2023 Jigsaw Operations LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package shadowsocks

import (
	"context"
	"errors"
	"time"

	"github.com/Jigsaw-Code/outline-sdk/transport"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

// NewStreamDialer creates a client that routes connections to a Shadowsocks proxy listening at
// the given StreamEndpoint, with `key` as the Shadowsocks encyption key.
func NewStreamDialer(endpoint transport.StreamEndpoint, key *EncryptionKey) (*StreamDialer, error) {
	if endpoint == nil {
		return nil, errors.New("argument endpoint must not be nil")
	}
	if key == nil {
		return nil, errors.New("argument key must not be nil")
	}
	d := StreamDialer{endpoint: endpoint, key: key, ClientDataWait: 10 * time.Millisecond}
	return &d, nil
}

type StreamDialer struct {
	endpoint transport.StreamEndpoint
	key      *EncryptionKey

	// SaltGenerator is used by Shadowsocks to generate the connection salts.
	// `SaltGenerator` can be `nil`, which defaults to [shadowsocks.RandomSaltGenerator].
	SaltGenerator SaltGenerator

	// ClientDataWait specifies the amount of time to wait for client data before sending
	// the Shadowsocks connection request to the proxy server. This value is 10 milliseconds
	// by default.
	//
	// StreamDialer has an optimization to send the initial client payload along with
	// the Shadowsocks connection request.  This saves one packet during connection, and also
	// reduces the distinctiveness of the connection pattern.
	//
	// Normally, the initial payload will be sent as soon as the socket is connected,
	// except for delays due to inter-process communication.  However, some protocols
	// expect the server to send data first, in which case there is no client payload.
	// We therefore use a short delay by default (10ms), longer than any reasonable IPC but shorter than
	// typical network latency.  (In an Android emulator, the 90th percentile delay
	// was ~1 ms.)  If no client payload is received by this time, we connect without it.
	ClientDataWait time.Duration
}

var _ transport.StreamDialer = (*StreamDialer)(nil)

// DialStream implements StreamDialer.DialStream using a Shadowsocks server.
//
// The Shadowsocks StreamDialer returns a connection after the connection to the proxy is established,
// but before the connection to the target is established. That means we cannot signal "connection refused"
// or "connection timeout" errors from the target to the application.
//
// This behavior breaks IPv6 Happy Eyeballs because the application IPv6 socket will connect successfully,
// even if the proxy fails to connect to the IPv6 destination. The broken Happy Eyeballs behavior makes
// IPv6 unusable if the proxy cannot use IPv6.
//
// We can't easily fix that issue because Shadowsocks, unlike SOCKS, does not have a way to indicate
// whether the target connection is successful. Even if that was possible, we want to wait until we have
// initial data from the application in order to send the Shadowsocks salt, SOCKS address and initial data
// all in one packet. This makes the size of the initial packet hard to predict, avoiding packet size
// fingerprinting. We can only get the application initial data if we return a connection first.
func (c *StreamDialer) DialStream(ctx context.Context, remoteAddr string) (transport.StreamConn, error) {
	socksTargetAddr := socks.ParseAddr(remoteAddr)
	if socksTargetAddr == nil {
		return nil, errors.New("failed to parse target address")
	}
	proxyConn, err := c.endpoint.ConnectStream(ctx)
	if err != nil {
		return nil, err
	}
	ssw := NewWriter(proxyConn, c.key)
	if c.SaltGenerator != nil {
		ssw.SetSaltGenerator(c.SaltGenerator)
	}
	_, err = ssw.LazyWrite(socksTargetAddr)
	if err != nil {
		proxyConn.Close()
		return nil, errors.New("failed to write target address")
	}
	time.AfterFunc(c.ClientDataWait, func() {
		ssw.Flush()
	})
	ssr := NewReader(proxyConn, c.key)
	return transport.WrapConn(proxyConn, ssr, ssw), nil
}
