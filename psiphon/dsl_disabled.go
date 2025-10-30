//go:build !PSIPHON_ENABLE_DSL_CLIENT

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

package psiphon

import (
	"context"
)

func DSLEnabled() bool {
	return false
}

func runUntunneledDSLFetcher(
	_ context.Context,
	_ *Config,
	_ *InproxyBrokerClientManager,
	_ <-chan struct{}) {
}

func runTunneledDSLFetcher(
	_ context.Context,
	_ *Config,
	_ func() *Tunnel,
	_ <-chan struct{}) {
}

func init() {
	compressTacticsEnabled = false
}
