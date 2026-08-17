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

func TestProxyLimitsDynamicRates(t *testing.T) {

	limits, err := NewProxyLimits(&ProxyLimitsConfig{
		MaxCommonClients:                 1,
		MaxPersonalClients:               1,
		PersonalUpstreamBytesPerSecond:   30,
		PersonalDownstreamBytesPerSecond: 40,
	})
	if err != nil {
		t.Fatal(err)
	}

	newConn := func() *ThrottledConn {
		return NewThrottledConn(nil, true, RateLimits{
			ReadBytesPerSecond:  99,
			WriteBytesPerSecond: 99,
		})
	}

	check := func(conn *ThrottledConn, read, write int64) {
		t.Helper()
		if value := conn.readBytesPerSecond.Load(); value != read {
			t.Fatalf("unexpected read rate: %d != %d", value, read)
		}
		if value := conn.writeBytesPerSecond.Load(); value != write {
			t.Fatalf("unexpected write rate: %d != %d", value, write)
		}
	}

	commonConn := newConn()
	personalConn := newConn()
	limits.RegisterCommonConn(commonConn)
	limits.RegisterPersonalConn(personalConn)

	check(commonConn, 0, 0)
	check(personalConn, 40, 30)

	err = limits.SetCommonLimits(1, 10, 20)
	if err != nil {
		t.Fatal(err)
	}
	check(commonConn, 20, 10)
	check(personalConn, 40, 30)

	err = limits.SetPersonalLimits(1, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	check(commonConn, 20, 10)
	check(personalConn, 0, 0)

	limits.UnregisterConn(commonConn)
	limits.UnregisterConn(personalConn)

	err = limits.SetCommonLimits(1, 50, 60)
	if err != nil {
		t.Fatal(err)
	}
	err = limits.SetPersonalLimits(1, 70, 80)
	if err != nil {
		t.Fatal(err)
	}
	check(commonConn, 20, 10)
	check(personalConn, 0, 0)

	lateCommonConn := newConn()
	latePersonalConn := newConn()
	limits.RegisterCommonConn(lateCommonConn)
	limits.RegisterPersonalConn(latePersonalConn)

	check(lateCommonConn, 60, 50)
	check(latePersonalConn, 80, 70)
}

func TestProxyLimitsReducedDynamicRates(t *testing.T) {

	now := time.Now().UTC().Truncate(time.Minute)
	start := now.Add(time.Hour)
	end := now.Add(2 * time.Hour)
	limits, err := NewProxyLimits(&ProxyLimitsConfig{
		MaxCommonClients:                 1,
		CommonUpstreamBytesPerSecond:     100,
		CommonDownstreamBytesPerSecond:   200,
		MaxPersonalClients:               1,
		PersonalUpstreamBytesPerSecond:   300,
		PersonalDownstreamBytesPerSecond: 400,
		ReducedStartTime:                 start.Format("15:04"),
		ReducedEndTime:                   end.Format("15:04"),
		ReducedUpstreamBytesPerSecond:    10,
		ReducedDownstreamBytesPerSecond:  20,
	})
	if err != nil {
		t.Fatal(err)
	}

	commonConn := NewThrottledConn(nil, true, RateLimits{})
	personalConn := NewThrottledConn(nil, true, RateLimits{})
	limits.RegisterCommonConn(commonConn)
	limits.RegisterPersonalConn(personalConn)
	defer limits.UnregisterConn(commonConn)
	defer limits.UnregisterConn(personalConn)

	check := func(conn *ThrottledConn, read, write int64) {
		t.Helper()
		if value := conn.readBytesPerSecond.Load(); value != read {
			t.Fatalf("unexpected read rate: %d != %d", value, read)
		}
		if value := conn.writeBytesPerSecond.Load(); value != write {
			t.Fatalf("unexpected write rate: %d != %d", value, write)
		}
	}

	check(commonConn, 200, 100)
	check(personalConn, 400, 300)
	if limits.reducedTimer == nil {
		t.Fatal("reduced timer not started")
	}

	limits.mutex.Lock()
	limits.applyScheduledRateLimitsLocked(start.Add(30 * time.Minute))
	limits.mutex.Unlock()
	check(commonConn, 20, 10)
	check(personalConn, 20, 10)

	limits.mutex.Lock()
	limits.applyScheduledRateLimitsLocked(end.Add(30 * time.Minute))
	limits.mutex.Unlock()
	check(commonConn, 200, 100)
	check(personalConn, 400, 300)

	limits.UnregisterConn(commonConn)
	limits.UnregisterConn(personalConn)
	if limits.reducedTimer != nil {
		t.Fatal("reduced timer not stopped")
	}
}
