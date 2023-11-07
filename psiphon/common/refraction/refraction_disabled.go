//go:build !PSIPHON_ENABLE_REFRACTION_NETWORKING
// +build !PSIPHON_ENABLE_REFRACTION_NETWORKING

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

package refraction

import (
	"context"
	"net"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// Enabled indicates if Refraction Networking functionality is enabled.
func Enabled() bool {
	return false
}

// Listener is a net.Listener.
type Listener struct {
	net.Listener
}

// Listen creates a new Refraction Networking listener.
func Listen(_ string) (net.Listener, error) {
	return nil, errors.TraceNew("operation is not enabled")
}

// DialTapDance establishes a new Tapdance connection to a Tapdance station.
func DialTapDance(_ context.Context, _ bool, _ string, _ Dialer, _ string) (net.Conn, error) {
	return nil, errors.TraceNew("operation is not enabled")
}

// DialConjure establishes a new Conjure connection to a Conjure station.
func DialConjure(_ context.Context, _ bool, _ string, _ Dialer, _ string, _ *ConjureConfig) (net.Conn, error) {
	return nil, errors.TraceNew("operation is not enabled")
}

func DeleteCachedConjureRegistration(_ *ConjureConfig) {
}
