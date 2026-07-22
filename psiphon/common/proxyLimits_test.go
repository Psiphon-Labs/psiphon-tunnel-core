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

package common

import (
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

func TestProxyLimitsReduced(t *testing.T) {
	err := runTestProxyLimitsReduced()
	if err != nil {
		t.Error(errors.Trace(err).Error())
	}
}

func runTestProxyLimitsReduced() error {

	now := time.Now().UTC()
	minuteOfDay := now.Hour()*60 + now.Minute()

	addMinutes := func(minute, delta int) int {
		m := (minute + delta) % (24 * 60)
		if m < 0 {
			m += 24 * 60
		}
		return m
	}

	// Test: inside reduced period

	start := addMinutes(minuteOfDay, -60)
	end := addMinutes(minuteOfDay, 60)

	config := &ProxyLimitsConfig{
		MaxCommonClients:                10,
		CommonUpstreamBytesPerSecond:    100,
		CommonDownstreamBytesPerSecond:  200,
		ReducedMaxCommonClients:         5,
		ReducedUpstreamBytesPerSecond:   10,
		ReducedDownstreamBytesPerSecond: 20,

		MaxPersonalClients:               3,
		PersonalUpstreamBytesPerSecond:   300,
		PersonalDownstreamBytesPerSecond: 400,
	}

	config.ReducedStartTime = time.Unix(int64(start*60), 0).UTC().Format("15:04")
	config.ReducedEndTime = time.Unix(int64(end*60), 0).UTC().Format("15:04")

	limits, err := NewProxyLimits(config)
	if err != nil {
		return errors.Trace(err)
	}

	maxAnnouncements, maxClients, activeClients,
		upstreamBytesPerSecond, downstreamBytesPerSecond := limits.GetCommonLimits()

	if maxAnnouncements != 5 || maxClients != 5 || activeClients != 0 {
		return errors.TraceNew("unexpected reduced limits")
	}
	if upstreamBytesPerSecond != 10 || downstreamBytesPerSecond != 20 {
		return errors.TraceNew("unexpected reduced rate limits")
	}

	// Reduced rates, but not reduced max clients, apply to personal pairing.

	maxAnnouncements, maxClients, activeClients,
		upstreamBytesPerSecond, downstreamBytesPerSecond = limits.GetPersonalLimits()

	if maxAnnouncements != 3 || maxClients != 3 || activeClients != 0 {
		return errors.TraceNew("unexpected personal limits")
	}
	if upstreamBytesPerSecond != 10 || downstreamBytesPerSecond != 20 {
		return errors.TraceNew("unexpected reduced personal rate limits")
	}

	// Test: outside reduced period

	start = addMinutes(minuteOfDay, 60)
	end = addMinutes(minuteOfDay, 120)

	config.ReducedStartTime = time.Unix(int64(start*60), 0).UTC().Format("15:04")
	config.ReducedEndTime = time.Unix(int64(end*60), 0).UTC().Format("15:04")

	limits, err = NewProxyLimits(config)
	if err != nil {
		return errors.Trace(err)
	}

	maxAnnouncements, maxClients, activeClients,
		upstreamBytesPerSecond, downstreamBytesPerSecond = limits.GetCommonLimits()

	if maxAnnouncements != 10 || maxClients != 10 || activeClients != 0 {
		return errors.TraceNew("unexpected common limits")
	}
	if upstreamBytesPerSecond != 100 || downstreamBytesPerSecond != 200 {
		return errors.TraceNew("unexpected common rate limits")
	}

	maxAnnouncements, maxClients, activeClients,
		upstreamBytesPerSecond, downstreamBytesPerSecond = limits.GetPersonalLimits()

	if maxAnnouncements != 3 || maxClients != 3 || activeClients != 0 {
		return errors.TraceNew("unexpected personal limits")
	}
	if upstreamBytesPerSecond != 300 || downstreamBytesPerSecond != 400 {
		return errors.TraceNew("unexpected personal rate limits")
	}

	// Test: reduced rate values of 0 inherit the base rates for each kind.

	start = addMinutes(minuteOfDay, -60)
	end = addMinutes(minuteOfDay, 60)

	config.ReducedStartTime = time.Unix(int64(start*60), 0).UTC().Format("15:04")
	config.ReducedEndTime = time.Unix(int64(end*60), 0).UTC().Format("15:04")
	config.ReducedUpstreamBytesPerSecond = 0
	config.ReducedDownstreamBytesPerSecond = 0

	limits, err = NewProxyLimits(config)
	if err != nil {
		return errors.Trace(err)
	}

	_, _, _, upstreamBytesPerSecond, downstreamBytesPerSecond = limits.GetCommonLimits()

	if upstreamBytesPerSecond != 100 || downstreamBytesPerSecond != 200 {
		return errors.TraceNew("unexpected inherited reduced rate limits")
	}

	_, _, _, upstreamBytesPerSecond, downstreamBytesPerSecond = limits.GetPersonalLimits()

	if upstreamBytesPerSecond != 300 || downstreamBytesPerSecond != 400 {
		return errors.TraceNew("unexpected inherited personal rate limits")
	}

	// Test: a reduced max common clients value of 0 inherits the base max
	// common clients, supporting a reduced-rates-only schedule.

	config.ReducedMaxCommonClients = 0
	config.ReducedUpstreamBytesPerSecond = 10
	config.ReducedDownstreamBytesPerSecond = 20

	limits, err = NewProxyLimits(config)
	if err != nil {
		return errors.Trace(err)
	}

	maxAnnouncements, maxClients, _,
		upstreamBytesPerSecond, downstreamBytesPerSecond = limits.GetCommonLimits()

	if maxAnnouncements != 10 || maxClients != 10 {
		return errors.TraceNew("unexpected inherited max common clients")
	}
	if upstreamBytesPerSecond != 10 || downstreamBytesPerSecond != 20 {
		return errors.TraceNew("unexpected reduced rate limits")
	}

	// Test: all reduced values 0 is a valid schedule; all base values apply.

	config.ReducedUpstreamBytesPerSecond = 0
	config.ReducedDownstreamBytesPerSecond = 0

	limits, err = NewProxyLimits(config)
	if err != nil {
		return errors.Trace(err)
	}

	_, maxClients, _,
		upstreamBytesPerSecond, downstreamBytesPerSecond = limits.GetCommonLimits()

	if maxClients != 10 || upstreamBytesPerSecond != 100 || downstreamBytesPerSecond != 200 {
		return errors.TraceNew("unexpected base limits")
	}

	// Test: reduced max common clients must remain <= max common clients.

	config.ReducedMaxCommonClients = 11
	_, err = NewProxyLimits(config)
	if err == nil {
		return errors.TraceNew("unexpected NewProxyLimits success")
	}

	// Dynamic limit changes are not supported when reduced schedule
	// parameters are configured.

	config.ReducedMaxCommonClients = 5
	limits, err = NewProxyLimits(config)
	if err != nil {
		return errors.Trace(err)
	}

	if limits.SetCommonLimits(10, 100, 200) == nil {
		return errors.TraceNew("unexpected SetCommonLimits success")
	}

	if limits.SetPersonalLimits(3, 300, 400) == nil {
		return errors.TraceNew("unexpected SetPersonalLimits success")
	}

	return nil
}
