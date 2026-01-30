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

package inproxy

import (
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

func TestReduced(t *testing.T) {
	err := runTestReduced()
	if err != nil {
		t.Error(errors.Trace(err).Error())
	}
}

func runTestReduced() error {

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

	config := &ProxyConfig{
		MaxClients:                           10,
		ReducedMaxClients:                    5,
		LimitUpstreamBytesPerSecond:          100,
		LimitDownstreamBytesPerSecond:        200,
		ReducedLimitUpstreamBytesPerSecond:   10,
		ReducedLimitDownstreamBytesPerSecond: 20,
	}

	config.ReducedStartTime = time.Unix(int64(start*60), 0).UTC().Format("15:04")
	config.ReducedEndTime = time.Unix(int64(end*60), 0).UTC().Format("15:04")

	p, err := NewProxy(config)
	if err != nil {
		return errors.Trace(err)
	}

	maxClients1, until := p.isReducedUntil()
	maxClients2, limits := p.getLimits()

	if maxClients1 != 5 || maxClients2 != 5 {
		return errors.TraceNew("unexpected maxClients")
	}
	if until.IsZero() || time.Until(until) <= 0 {
		return errors.TraceNew("unexpected until")
	}
	if limits.ReadBytesPerSecond != 10 || limits.WriteBytesPerSecond != 20 {
		return errors.TraceNew("unexpected rate limits")
	}

	// Test: outside reduced period

	start = addMinutes(minuteOfDay, 60)
	end = addMinutes(minuteOfDay, 120)

	config.ReducedStartTime = time.Unix(int64(start*60), 0).UTC().Format("15:04")
	config.ReducedEndTime = time.Unix(int64(end*60), 0).UTC().Format("15:04")

	p, err = NewProxy(config)
	if err != nil {
		return errors.Trace(err)
	}

	maxClients1, until = p.isReducedUntil()
	maxClients2, limits = p.getLimits()

	if maxClients1 != 10 || maxClients2 != 10 {
		return errors.TraceNew("unexpected maxClients")
	}
	if !until.IsZero() {
		return errors.TraceNew("unexpected until")
	}
	if limits.ReadBytesPerSecond != 100 || limits.WriteBytesPerSecond != 200 {
		return errors.TraceNew("unexpected rate limits")
	}

	return nil
}
