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

#import <Foundation/Foundation.h>
#import "ReachabilityProtocol.h"

NS_ASSUME_NONNULL_BEGIN

@interface NetworkID : NSObject

/// The network ID contains potential PII. In tunnel-core, the network ID
/// is used only locally in the client and not sent to the server.
///
/// See network ID requirements here:
/// https://godoc.org/github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon#NetworkIDGetter
///
/// All interface-address-based network IDs use the interface's IPv4 address if it has a usable one, e.g.
/// "WIFI-192.0.2.1", and otherwise only the first 32 bits of one of its unique local or global IPv6 addresses,
/// e.g. "WIFI-fd12:3456::/32"; see NetworkInterfaceSelectAddress. If no address qualifies, the network ID
/// contains only the network type.
///
/// On iOS >=12 the network type and the active interface name are both taken from one read of the reachability
/// object's DefaultRouteMonitor path state, so that during a handoff the type of one network is not paired with the
/// interface of another. The interface's address is read afterwards, so it may have changed or be missing by then.
/// Unless the VPN check returns "VPN" first, a path state whose status is not reachable gives "UNKNOWN".
///
/// @param reachability DefaultRouteMonitor, on iOS >=12, whose path state determines the network type and the
/// active interface name.
/// @param currentNetworkStatus Used only on iOS <12, or when the reachability object has no path state, to determine
/// the network type and, on iOS <12, the active interface. With no path state on iOS >=12, an address-based network
/// type gives only the bare type, with a warning.
/// @param tunnelWholeDevice False if library is used in non-VPN mode, true otherwise.
/// @param outWarn If non-nil, then a non-fatal error occurred while determining the network ID and a valid network ID will still be returned.
+ (NSString *)getNetworkIDWithReachability:(id<ReachabilityProtocol>)reachability
                   andCurrentNetworkStatus:(NetworkReachability)currentNetworkStatus
                         tunnelWholeDevice:(BOOL)tunnelWholeDevice
                                   warning:(NSError *_Nullable *_Nonnull)outWarn;

@end

NS_ASSUME_NONNULL_END
