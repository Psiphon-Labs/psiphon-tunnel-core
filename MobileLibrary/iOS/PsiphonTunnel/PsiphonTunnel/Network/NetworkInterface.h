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
#import <Network/path.h>

NS_ASSUME_NONNULL_BEGIN

/// NetworkPathState represents the state of the network path on the device.
@interface NetworkPathState : NSObject

/// Network path state.
@property (nonatomic, nullable) nw_path_t path;

/// Default active interface available to the network path.
@property (nonatomic, nullable) nw_interface_t defaultActiveInterface;

@end

/// NetworkInterface provides a set of functions for discovering active network interfaces on the device.
@interface NetworkInterface : NSObject

/// Returns list of active interfaces excluding the loopback interface which support communicating with IPv4, or IPv6, addresses.
+ (NSSet<NSString*>*_Nullable)activeInterfaces;

/// Returns the currrent network path state and default active interface. The default active interface is found by mapping the active
/// interface type used by the current network path to the first interface available to that path which is of the same type (e.g. WiFi, Cellular,
/// etc.). This allows for the possibility of returning a non-default active interface in the scenario where there are other active interfaces
/// which share the same type as the default active interface. This design limitation is present because querying the routing table is not
/// supported on iOS; therefore we cannot query the routing table for the interface associated with the default route. Fortunately the
/// selected interface should always be capable of routing traffic to the internet, even if a non-default active interface is chosen.
/// @param activeInterfaces If non-nil, then only interfaces available to the current network path which are present in this list will
/// be considered when searching for the default active interface. If nil, then all interfaces available to the current network path will be
/// searched.
/// @return The current network path state. See NetworkPathState for further details.
+ (NetworkPathState*)networkPathState:(NSSet<NSString*>*_Nullable)activeInterfaces API_AVAILABLE(macos(10.14), ios(12.0), watchos(5.0), tvos(12.0));

@end

NS_ASSUME_NONNULL_END
