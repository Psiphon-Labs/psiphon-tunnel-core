// +build !android,!linux,!darwin

/*
 * Copyright (c) 2014, Psiphon Inc.
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

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// LookupIP resolves a hostname.
func LookupIP(ctx context.Context, host string, config *DialConfig) ([]net.IP, error) {

	if config.DeviceBinder != nil {
		return nil, errors.TraceNew("LookupIP with DeviceBinder not supported on this platform")
	}

	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)

	// Remove domain names from "net" error messages.
	if err != nil && !GetEmitNetworkParameters() {
		err = RedactNetError(err)
	}

	if err != nil {
		return nil, errors.Trace(err)
	}

	ips := make([]net.IP, len(addrs))
	for i, addr := range addrs {
		ips[i] = addr.IP
	}

	return ips, nil
}
