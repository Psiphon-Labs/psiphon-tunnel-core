// +build MARIONETTE

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

Package marionette wraps github.com/redjack/marionette with net.Listener and
net.Conn types that provide a drop-in replacement for net.TCPConn.

Each marionette session has exactly one stream, which is the equivilent of a TCP
stream.

*/
package marionette

import (
	"context"
	"net"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	redjack_marionette "github.com/redjack/marionette"
	"github.com/redjack/marionette/mar"
	_ "github.com/redjack/marionette/plugins"
	"go.uber.org/zap"
)

func init() {
	// Override the Logger initialized by redjack_marionette.init()
	redjack_marionette.Logger = zap.NewNop()
}

// Enabled indicates if Marionette functionality is enabled.
func Enabled() bool {
	return true
}

// Listener is a net.Listener.
type Listener struct {
	net.Listener
}

// Listen creates a new Marionette Listener. The address input should not
// include a port number as the port is defined in the Marionette format.
func Listen(address, format string) (net.Listener, error) {

	data, err := mar.ReadFormat(format)
	if err != nil {
		return nil, errors.Trace(err)
	}

	doc, err := mar.Parse(redjack_marionette.PartyServer, data)
	if err != nil {
		return nil, errors.Trace(err)
	}

	listener, err := redjack_marionette.Listen(doc, address)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return &Listener{Listener: listener}, nil
}

// Dial establishes a new Marionette session and stream to the server
// specified by address. The address input should not include a port number as
// that's defined in the Marionette format.
func Dial(
	ctx context.Context,
	netDialer common.NetDialer,
	format string,
	address string) (net.Conn, error) {

	data, err := mar.ReadFormat(format)
	if err != nil {
		return nil, errors.Trace(err)
	}

	doc, err := mar.Parse(redjack_marionette.PartyClient, data)
	if err != nil {
		return nil, errors.Trace(err)
	}

	streamSet := redjack_marionette.NewStreamSet()

	dialer := redjack_marionette.NewDialer(doc, address, streamSet)

	dialer.Dialer = netDialer

	err = dialer.Open()
	if err != nil {
		streamSet.Close()
		return nil, errors.Trace(err)
	}

	// dialer.Dial does not block on network I/O
	conn, err := dialer.Dial()
	if err != nil {
		streamSet.Close()
		dialer.Close()
		return nil, errors.Trace(err)
	}

	return &Conn{
		Conn:      conn,
		streamSet: streamSet,
		dialer:    dialer,
	}, nil
}

// Conn is a net.Conn and psiphon/common.Closer.
type Conn struct {
	net.Conn

	streamSet *redjack_marionette.StreamSet
	dialer    *redjack_marionette.Dialer
}

func (conn *Conn) Close() error {
	if conn.IsClosed() {
		return nil
	}
	retErr := conn.Conn.Close()
	err := conn.streamSet.Close()
	if retErr == nil && err != nil {
		retErr = err
	}
	err = conn.dialer.Close()
	if retErr == nil && err != nil {
		retErr = err
	}
	return retErr
}

func (conn *Conn) IsClosed() bool {
	return conn.dialer.Closed()
}
