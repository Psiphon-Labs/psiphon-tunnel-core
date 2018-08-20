// +build !TAPDANCE

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

package tapdance

import (
	"context"
	"errors"
	"net"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

var disabledError = errors.New("operation is not enabled")

// Enabled indicates if Tapdance functionality is enabled.
func Enabled() bool {
	return false
}

// Listener is a net.Listener.
type Listener struct {
	net.Listener
}

// Listen creates a new Tapdance listener.
func Listen(_ string) (*Listener, error) {
	return nil, common.ContextError(disabledError)
}

// Dial establishes a new Tapdance session to a Tapdance station.
func Dial(_ context.Context, _ string, _ common.NetDialer, _ string) (net.Conn, error) {
	return nil, common.ContextError(disabledError)
}
