/*
 * Copyright (c) 2025, Psiphon Inc.
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
	"context"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/dsl"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
)

func dslReloadRelayTactics(support *SupportServices) error {

	// Assumes no GeoIP targeting for DSL relay tactics.

	dslRelay := support.dslRelay

	if dslRelay == nil {
		return nil
	}

	p, err := support.ServerTacticsParametersCache.Get(NewGeoIPData())
	if err != nil {
		return errors.Trace(err)
	}
	defer p.Close()
	if p.IsNil() {
		return nil
	}

	dslRelay.SetRequestParameters(
		p.Int(parameters.DSLRelayMaxHttpConns),
		p.Int(parameters.DSLRelayMaxHttpIdleConns),
		p.Duration(parameters.DSLRelayHttpIdleConnTimeout),
		p.Duration(parameters.DSLRelayRequestTimeout),
		p.Int(parameters.DSLRelayRetryCount))

	dslRelay.SetCacheParameters(
		p.Duration(parameters.DSLRelayCacheTTL),
		p.Int(parameters.DSLRelayCacheMaxSize))

	return nil
}

func dslHandleRequest(
	ctx context.Context,
	support *SupportServices,
	extendTimeout func(time.Duration),
	clientIP string,
	clientGeoIPData common.GeoIPData,
	isClientTunneled bool,
	requestPayload []byte) ([]byte, error) {

	relay := support.dslRelay

	if relay == nil {
		return dsl.GetRelayGenericErrorResponse(),
			errors.TraceNew("DSL relay not configured")
	}

	responsePayload, err := relay.HandleRequest(
		ctx,
		extendTimeout,
		clientIP,
		clientGeoIPData,
		isClientTunneled,
		requestPayload)
	if err != nil {
		return dsl.GetRelayGenericErrorResponse(),
			errors.Trace(err)
	}

	return responsePayload, nil
}
