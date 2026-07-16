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
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// ProxyLimitsConfig specifies initial shared proxy limits. For each kind,
// common and personal, a max clients value of 0 disables the kind. At least
// one kind must be enabled. Rate values of 0 mean no rate limit. Reduced
// values of 0 mean the corresponding base values apply. When any reduced
// parameters are configured, limits cannot be changed dynamically with
// SetCommonLimits or SetPersonalLimits.
//
// During the reduced schedule, the reduced max clients value applies to
// common pairing only, while the reduced rates apply to both common and
// personal pairing.
//
// Max announcements are not explicitly configured: the effective max
// announcements for each kind is its max clients, as reduced by any
// OverrideMaxAnnouncements override.
//
// Max announcement overrides should be applied via tactics. One use case for
// fewer concurrent inproxy proxy announcements is reducing broker load in
// low demand conditions, with a tradeoff of potentially longer client wait
// times; the other primary use case is minimizing the number of
// announcements that match but go on to fail to acquire a client slot when
// sharing proxy limits with another proxy.
type ProxyLimitsConfig struct {
	MaxCommonClients               int
	CommonUpstreamBytesPerSecond   int
	CommonDownstreamBytesPerSecond int

	MaxPersonalClients               int
	PersonalUpstreamBytesPerSecond   int
	PersonalDownstreamBytesPerSecond int

	ReducedStartTime                string
	ReducedEndTime                  string
	ReducedMaxCommonClients         int
	ReducedUpstreamBytesPerSecond   int
	ReducedDownstreamBytesPerSecond int
}

// ProxyLimits provides a shared, dynamic limit state for proxies, including
// inproxy.Proxy and light.Proxy, which allows for coordinated enforcement of
// limits across multiple proxy instances.
//
// Max client slots are enforced across all instances sharing the state, via
// TryAcquireCommonClient and TryAcquirePersonalClient. Max announcement
// values are advisory: each announcing proxy instance applies the max value
// independently.
type ProxyLimits struct {
	mutex sync.Mutex

	maxCommonClients               int
	commonUpstreamBytesPerSecond   int
	commonDownstreamBytesPerSecond int

	reducedEnabled                  bool
	reducedStartMinute              int
	reducedEndMinute                int
	reducedMaxCommonClients         int
	reducedUpstreamBytesPerSecond   int
	reducedDownstreamBytesPerSecond int

	maxPersonalClients               int
	personalUpstreamBytesPerSecond   int
	personalDownstreamBytesPerSecond int

	overrideMaxCommonAnnouncements   int
	overrideMaxPersonalAnnouncements int

	activeCommonClients   int
	activePersonalClients int
}

// ProxyLimitReleaseFunc releases a proxy client slot acquired from
// ProxyLimits. Calling a release function more than once has no effect after
// the first call.
type ProxyLimitReleaseFunc func()

// NewProxyLimits initializes a ProxyLimits.
func NewProxyLimits(config *ProxyLimitsConfig) (*ProxyLimits, error) {

	if config == nil {
		return nil, errors.TraceNew("nil ProxyLimitsConfig")
	}

	if config.MaxCommonClients < 0 || config.MaxPersonalClients < 0 {
		return nil, errors.TraceNew("invalid ProxyLimitsConfig")
	}

	if config.MaxCommonClients <= 0 &&
		config.MaxPersonalClients <= 0 {
		return nil, errors.TraceNew("invalid ProxyLimitsConfig")
	}

	proxyLimits := &ProxyLimits{}

	err := proxyLimits.setCommonLimitsLocked(
		config.MaxCommonClients,
		config.CommonUpstreamBytesPerSecond,
		config.CommonDownstreamBytesPerSecond)
	if err != nil {
		return nil, errors.Trace(err)
	}

	err = proxyLimits.setPersonalLimitsLocked(
		config.MaxPersonalClients,
		config.PersonalUpstreamBytesPerSecond,
		config.PersonalDownstreamBytesPerSecond)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if config.ReducedStartTime != "" ||
		config.ReducedEndTime != "" ||
		config.ReducedMaxCommonClients != 0 ||
		config.ReducedUpstreamBytesPerSecond != 0 ||
		config.ReducedDownstreamBytesPerSecond != 0 {

		err = validateProxyLimits(
			config.ReducedMaxCommonClients,
			config.ReducedUpstreamBytesPerSecond,
			config.ReducedDownstreamBytesPerSecond)
		if err != nil {
			return nil, errors.Trace(err)
		}

		if config.ReducedMaxCommonClients > proxyLimits.maxCommonClients {
			return nil, errors.TraceNew("invalid reduced limits")
		}

		startMinute, err := ParseTimeOfDayMinutes(config.ReducedStartTime)
		if err != nil {
			return nil, errors.Trace(err)
		}

		endMinute, err := ParseTimeOfDayMinutes(config.ReducedEndTime)
		if err != nil {
			return nil, errors.Trace(err)
		}

		if startMinute == endMinute {
			return nil, errors.TraceNew("invalid reduced time range")
		}

		proxyLimits.reducedEnabled = true
		proxyLimits.reducedStartMinute = startMinute
		proxyLimits.reducedEndMinute = endMinute
		proxyLimits.reducedMaxCommonClients = config.ReducedMaxCommonClients
		proxyLimits.reducedUpstreamBytesPerSecond =
			config.ReducedUpstreamBytesPerSecond
		proxyLimits.reducedDownstreamBytesPerSecond =
			config.ReducedDownstreamBytesPerSecond
	}

	return proxyLimits, nil
}

// GetCommonLimits returns the current common pairing proxy limits and active
// client count. Reduced common limits are returned when the reduced schedule
// is active.
func (limits *ProxyLimits) GetCommonLimits() (
	maxAnnouncements int,
	maxClients int,
	activeClients int,
	upstreamBytesPerSecond int,
	downstreamBytesPerSecond int) {

	limits.mutex.Lock()
	defer limits.mutex.Unlock()

	maxAnnouncements, maxClients, upstreamBytesPerSecond, downstreamBytesPerSecond =
		limits.getCommonLimitsLocked(time.Now().UTC())

	return maxAnnouncements,
		maxClients,
		limits.activeCommonClients,
		upstreamBytesPerSecond,
		downstreamBytesPerSecond
}

// GetPersonalLimits returns the current personal pairing proxy limits and
// active client count. Reduced rates are returned when the reduced schedule
// is active; personal max clients are never reduced.
func (limits *ProxyLimits) GetPersonalLimits() (
	maxAnnouncements int,
	maxClients int,
	activeClients int,
	upstreamBytesPerSecond int,
	downstreamBytesPerSecond int) {

	limits.mutex.Lock()
	defer limits.mutex.Unlock()

	maxAnnouncements = limits.maxPersonalClients
	if limits.overrideMaxPersonalAnnouncements > 0 &&
		limits.overrideMaxPersonalAnnouncements < maxAnnouncements {
		maxAnnouncements = limits.overrideMaxPersonalAnnouncements
	}

	upstreamBytesPerSecond = limits.personalUpstreamBytesPerSecond
	downstreamBytesPerSecond = limits.personalDownstreamBytesPerSecond

	if limits.isReducedLocked(time.Now().UTC()) {

		// Reduced rate values of 0 mean the base rates apply.
		if limits.reducedUpstreamBytesPerSecond != 0 {
			upstreamBytesPerSecond = limits.reducedUpstreamBytesPerSecond
		}
		if limits.reducedDownstreamBytesPerSecond != 0 {
			downstreamBytesPerSecond = limits.reducedDownstreamBytesPerSecond
		}
	}

	return maxAnnouncements,
		limits.maxPersonalClients,
		limits.activePersonalClients,
		upstreamBytesPerSecond,
		downstreamBytesPerSecond
}

// SetCommonLimits sets common pairing proxy limits. Active clients are not
// disconnected or rethrottled when the limits change. Setting max clients to
// 0, disabling common pairing, is invalid when personal pairing is also
// disabled. Calls fail when reduced limits were configured.
func (limits *ProxyLimits) SetCommonLimits(
	maxClients int,
	upstreamBytesPerSecond int,
	downstreamBytesPerSecond int) error {

	limits.mutex.Lock()
	defer limits.mutex.Unlock()

	if limits.reducedEnabled {
		return errors.TraceNew("cannot set proxy limits with reduced limits configured")
	}

	if maxClients <= 0 && limits.maxPersonalClients <= 0 {
		return errors.TraceNew("invalid proxy limits")
	}

	return errors.Trace(limits.setCommonLimitsLocked(
		maxClients,
		upstreamBytesPerSecond,
		downstreamBytesPerSecond))
}

// SetPersonalLimits sets personal pairing proxy limits. Active clients are
// not disconnected or rethrottled when the limits change. Setting max
// clients to 0, disabling personal pairing, is invalid when common pairing
// is also disabled. Calls fail when reduced limits were configured.
func (limits *ProxyLimits) SetPersonalLimits(
	maxClients int,
	upstreamBytesPerSecond int,
	downstreamBytesPerSecond int) error {

	limits.mutex.Lock()
	defer limits.mutex.Unlock()

	if limits.reducedEnabled {
		return errors.TraceNew("cannot set proxy limits with reduced limits configured")
	}

	if maxClients <= 0 && limits.maxCommonClients <= 0 {
		return errors.TraceNew("invalid proxy limits")
	}

	return errors.Trace(limits.setPersonalLimitsLocked(
		maxClients,
		upstreamBytesPerSecond,
		downstreamBytesPerSecond))
}

// OverrideMaxAnnouncements sets or clears common and personal max
// announcement overrides. A value of 0 clears the override. When an override
// is set, the effective max announcements is the minimum of the override and
// max clients. Overrides should be set via tactics. See ProxyLimitsConfig.
func (limits *ProxyLimits) OverrideMaxAnnouncements(
	maxCommonAnnouncements int,
	maxPersonalAnnouncements int) error {

	if maxCommonAnnouncements < 0 || maxPersonalAnnouncements < 0 {
		return errors.TraceNew("invalid proxy limits")
	}

	limits.mutex.Lock()
	defer limits.mutex.Unlock()

	limits.overrideMaxCommonAnnouncements = maxCommonAnnouncements
	limits.overrideMaxPersonalAnnouncements = maxPersonalAnnouncements

	return nil
}

// TryAcquireCommonClient attempts to acquire one common client slot.
func (limits *ProxyLimits) TryAcquireCommonClient() (ProxyLimitReleaseFunc, bool) {
	return limits.tryAcquireClient(false)
}

// TryAcquirePersonalClient attempts to acquire one personal client slot.
func (limits *ProxyLimits) TryAcquirePersonalClient() (ProxyLimitReleaseFunc, bool) {
	return limits.tryAcquireClient(true)
}

func (limits *ProxyLimits) setCommonLimitsLocked(
	maxClients int,
	upstreamBytesPerSecond int,
	downstreamBytesPerSecond int) error {

	err := validateProxyLimits(
		maxClients,
		upstreamBytesPerSecond,
		downstreamBytesPerSecond)
	if err != nil {
		return errors.Trace(err)
	}

	limits.maxCommonClients = maxClients
	limits.commonUpstreamBytesPerSecond = upstreamBytesPerSecond
	limits.commonDownstreamBytesPerSecond = downstreamBytesPerSecond

	return nil
}

func (limits *ProxyLimits) setPersonalLimitsLocked(
	maxClients int,
	upstreamBytesPerSecond int,
	downstreamBytesPerSecond int) error {

	err := validateProxyLimits(
		maxClients,
		upstreamBytesPerSecond,
		downstreamBytesPerSecond)
	if err != nil {
		return errors.Trace(err)
	}

	limits.maxPersonalClients = maxClients
	limits.personalUpstreamBytesPerSecond = upstreamBytesPerSecond
	limits.personalDownstreamBytesPerSecond = downstreamBytesPerSecond

	return nil
}

func (limits *ProxyLimits) getCommonLimitsLocked(now time.Time) (
	maxAnnouncements int,
	maxClients int,
	upstreamBytesPerSecond int,
	downstreamBytesPerSecond int) {

	if limits.isReducedLocked(now) {

		// Reduced values of 0 mean the base values apply.
		maxClients = limits.reducedMaxCommonClients
		if maxClients == 0 {
			maxClients = limits.maxCommonClients
		}
		maxAnnouncements = maxClients

		upstreamBytesPerSecond = limits.reducedUpstreamBytesPerSecond
		if upstreamBytesPerSecond == 0 {
			upstreamBytesPerSecond = limits.commonUpstreamBytesPerSecond
		}
		downstreamBytesPerSecond = limits.reducedDownstreamBytesPerSecond
		if downstreamBytesPerSecond == 0 {
			downstreamBytesPerSecond = limits.commonDownstreamBytesPerSecond
		}
	} else {
		maxAnnouncements = limits.maxCommonClients
		maxClients = limits.maxCommonClients
		upstreamBytesPerSecond = limits.commonUpstreamBytesPerSecond
		downstreamBytesPerSecond = limits.commonDownstreamBytesPerSecond
	}

	if limits.overrideMaxCommonAnnouncements > 0 &&
		limits.overrideMaxCommonAnnouncements < maxAnnouncements {
		maxAnnouncements = limits.overrideMaxCommonAnnouncements
	}

	return
}

func (limits *ProxyLimits) isReducedLocked(now time.Time) bool {

	if !limits.reducedEnabled {
		return false
	}

	minute := now.Hour()*60 + now.Minute()
	if limits.reducedStartMinute < limits.reducedEndMinute {
		return minute >= limits.reducedStartMinute &&
			minute < limits.reducedEndMinute
	}

	return minute >= limits.reducedStartMinute ||
		minute < limits.reducedEndMinute
}

func (limits *ProxyLimits) tryAcquireClient(
	isPersonal bool) (ProxyLimitReleaseFunc, bool) {

	limits.mutex.Lock()
	defer limits.mutex.Unlock()

	if !isPersonal {
		_, maxClients, _, _ := limits.getCommonLimitsLocked(time.Now().UTC())
		if limits.activeCommonClients >= maxClients {
			return nil, false
		}
		limits.activeCommonClients++
	} else {
		if limits.activePersonalClients >= limits.maxPersonalClients {
			return nil, false
		}
		limits.activePersonalClients++
	}

	released := atomic.Bool{}
	return func() {
		if released.Swap(true) {
			return
		}

		limits.mutex.Lock()
		defer limits.mutex.Unlock()

		if !isPersonal {
			limits.activeCommonClients--
		} else {
			limits.activePersonalClients--
		}
	}, true
}

func validateProxyLimits(
	maxClients int,
	upstreamBytesPerSecond int,
	downstreamBytesPerSecond int) error {

	if maxClients < 0 ||
		upstreamBytesPerSecond < 0 ||
		downstreamBytesPerSecond < 0 {
		return errors.TraceNew("invalid proxy limits")
	}

	return nil
}
