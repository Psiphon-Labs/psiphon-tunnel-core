/*
 * Copyright (c) 2023, Psiphon Inc.
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

package psiphon

import (
	"context"
	"net"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/obfuscator"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

// TLSTunnelConfig specifies the behavior of a TLSTunnelConn.
type TLSTunnelConfig struct {

	// CustomTLSConfig is the parameters that will be used to esablish a new
	// TLS connection with CustomTLSDial.
	CustomTLSConfig *CustomTLSConfig

	// UseObfuscatedSessionTickets indicates whether to use obfuscated session
	// tickets.
	UseObfuscatedSessionTickets bool

	// The following values are used to create the TLS passthrough message.

	ObfuscatedKey         string
	ObfuscatorPaddingSeed *prng.Seed
}

// TLSTunnelConn is a network connection that tunnels net.Conn flows over TLS.
type TLSTunnelConn struct {
	net.Conn
	tlsPadding        int
	resumedTLSSession bool
}

// DialTLSTunnel returns an initialized tls-tunnel connection.
func DialTLSTunnel(
	ctx context.Context,
	tlsTunnelConfig *TLSTunnelConfig,
	dialConfig *DialConfig,
	tlsOSSHApplyTrafficShaping bool,
	tlsOSSHMinTLSPadding,
	tlsOSSHMaxTLSPadding int,
) (*TLSTunnelConn, error) {

	tlsPadding,
		err :=
		tlsTunnelTLSPadding(
			tlsOSSHApplyTrafficShaping,
			tlsOSSHMinTLSPadding,
			tlsOSSHMaxTLSPadding,
			tlsTunnelConfig.ObfuscatorPaddingSeed)
	if err != nil {
		return nil, errors.Trace(err)
	}

	tlsConfig := &CustomTLSConfig{
		Parameters:                    tlsTunnelConfig.CustomTLSConfig.Parameters,
		Dial:                          NewTCPDialer(dialConfig),
		DialAddr:                      tlsTunnelConfig.CustomTLSConfig.DialAddr,
		SNIServerName:                 tlsTunnelConfig.CustomTLSConfig.SNIServerName,
		VerifyServerName:              tlsTunnelConfig.CustomTLSConfig.VerifyServerName,
		VerifyPins:                    tlsTunnelConfig.CustomTLSConfig.VerifyPins,
		SkipVerify:                    tlsTunnelConfig.CustomTLSConfig.SkipVerify,
		TLSProfile:                    tlsTunnelConfig.CustomTLSConfig.TLSProfile,
		NoDefaultTLSSessionID:         tlsTunnelConfig.CustomTLSConfig.NoDefaultTLSSessionID,
		RandomizedTLSProfileSeed:      tlsTunnelConfig.CustomTLSConfig.RandomizedTLSProfileSeed,
		TLSPadding:                    tlsPadding,
		TrustedCACertificatesFilename: dialConfig.TrustedCACertificatesFilename,
		FragmentClientHello:           tlsTunnelConfig.CustomTLSConfig.FragmentClientHello,
		ClientSessionCache:            tlsTunnelConfig.CustomTLSConfig.ClientSessionCache,
	}

	if tlsTunnelConfig.UseObfuscatedSessionTickets {
		tlsConfig.ObfuscatedSessionTicketKey = tlsTunnelConfig.ObfuscatedKey
	}

	// As the passthrough message is unique and indistinguishable from a normal
	// TLS client random value, we set it unconditionally and not just for
	// protocols which may support passthrough (even for those protocols,
	// clients don't know which servers are configured to use it).

	passthroughMessage, err := obfuscator.MakeTLSPassthroughMessage(
		true,
		tlsTunnelConfig.ObfuscatedKey)
	if err != nil {
		return nil, errors.Trace(err)
	}
	tlsConfig.PassthroughMessage = passthroughMessage

	tlsDialer := NewCustomTLSDialer(tlsConfig)

	// As DialAddr is set in the CustomTLSConfig, no address is required here.
	conn, err := tlsDialer(ctx, "tcp", "")
	if err != nil {
		return nil, errors.Trace(err)
	}

	return &TLSTunnelConn{
		Conn:              conn,
		tlsPadding:        tlsPadding,
		resumedTLSSession: conn.resumedSession,
	}, nil
}

// tlsTunnelTLSPadding returns the padding length to apply with the TLS padding
// extension to the TLS conn established with NewCustomTLSDialer. See
// CustomTLSConfig.TLSPadding for details.
func tlsTunnelTLSPadding(
	tlsOSSHApplyTrafficShaping bool,
	tlsOSSHMinTLSPadding int,
	tlsOSSHMaxTLSPadding int,
	obfuscatorPaddingPRNGSeed *prng.Seed,
) (tlsPadding int,
	err error) {

	tlsPadding = 0

	if tlsOSSHApplyTrafficShaping {

		minPadding := tlsOSSHMinTLSPadding
		maxPadding := tlsOSSHMaxTLSPadding

		// Maximum padding size per RFC 7685
		if maxPadding > 65535 {
			maxPadding = 65535
		}

		if maxPadding > 0 {
			tlsPaddingPRNG, err := prng.NewPRNGWithSaltedSeed(obfuscatorPaddingPRNGSeed, "tls-padding")
			if err != nil {
				return 0, errors.Trace(err)
			}

			tlsPadding = tlsPaddingPRNG.Range(minPadding, maxPadding)
		}
	}

	return tlsPadding, nil
}

func (conn *TLSTunnelConn) GetMetrics() common.LogFields {
	logFields := make(common.LogFields)

	logFields["tls_padding"] = conn.tlsPadding
	logFields["resumed_session"] = conn.resumedTLSSession

	// Include metrics, such as fragmentor metrics, from the underlying dial
	// conn. Properties of subsequent underlying dial conns are not reflected
	// in these metrics; we assume that the first dial conn, which most likely
	// transits the various protocol handshakes, is most significant.
	underlyingMetrics, ok := conn.Conn.(common.MetricsSource)
	if ok {
		logFields.Add(underlyingMetrics.GetMetrics())
	}
	return logFields
}

func (conn *TLSTunnelConn) IsClosed() bool {
	closer, ok := conn.Conn.(common.Closer)
	if !ok {
		return false
	}
	return closer.IsClosed()
}
