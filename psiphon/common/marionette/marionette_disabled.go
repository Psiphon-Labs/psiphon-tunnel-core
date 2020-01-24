// +build !MARIONETTE

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

package marionette

import (
	"context"
	"net"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// Enabled indicates if Marionette functionality is enabled.
func Enabled() bool {
	return false
}

// Listener is a net.Listener.
type Listener struct {
	net.Listener
}

// Listen creates a new Marionette Listener. The address input should not
// include a port number as that's defined in the Marionette format.
func Listen(_, _ string) (net.Listener, error) {
	return nil, errors.TraceNew("operation is not enabled")
}

// Dial establishes a new Marionette session and stream to the server
// specified by address. The address input should not include a port number as
// that's defined in the Marionette format.
func Dial(_ context.Context, _ common.NetDialer, _ string, _ string) (net.Conn, error) {
	return nil, errors.TraceNew("operation is not enabled")
}
