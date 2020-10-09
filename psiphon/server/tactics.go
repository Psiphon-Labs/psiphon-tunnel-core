/*
 * Copyright (c) 2020, Psiphon Inc.
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

package server

import (
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
)

// GetServerTacticsParameters returns server-side tactics parameters for the
// specified GeoIP scope. GetServerTacticsParameters is designed to be called
// before the API handshake and does not filter by API parameters. IsNil
// guards must be used when accessing the returned ParametersAccessor.
func GetServerTacticsParameters(
	support *SupportServices,
	geoIPData GeoIPData) (parameters.ParametersAccessor, error) {

	nilAccessor := parameters.MakeNilParametersAccessor()

	tactics, err := support.TacticsServer.GetTactics(
		true, common.GeoIPData(geoIPData), make(common.APIParameters))
	if err != nil {
		return nilAccessor, errors.Trace(err)
	}

	if tactics == nil {
		// This server isn't configured with tactics.
		return nilAccessor, nil
	}

	// Tactics.Probability is ignored for server-side tactics.

	params, err := parameters.NewParameters(nil)
	if err != nil {
		return nilAccessor, errors.Trace(err)
	}
	_, err = params.Set("", false, tactics.Parameters)
	if err != nil {
		return nilAccessor, errors.Trace(err)
	}

	return params.Get(), nil
}
