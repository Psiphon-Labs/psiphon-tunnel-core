//go:build !PSIPHON_DISABLE_INPROXY && !android

/*
 * Copyright (c) 2023, Psiphon Inc.
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

func setPortMapperBindToDevice(_ WebRTCDialCoordinator) {
	// BindToDevice is not applied on iOS as tailscale.com/net/netns does not
	// have an equivalent to SetAndroidProtectFunc for iOS. At this time,
	// BindToDevice operations on iOS are legacy code and not required.
}
