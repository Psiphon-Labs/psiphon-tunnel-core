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
#import "ReachabilityProtocol.h"

NS_ASSUME_NONNULL_BEGIN

/// NetworkInterface provides a set of functions for discovering active network interfaces on the device.
@interface NetworkInterface : NSObject

/// Returns address assigned to the given interface. If the interface has no assigned addresses, or only has a link-local IPv6 address,
/// then nil is returned.
/// @param interfaceName Interface name. E.g. "en0".
/// @param outError If non-nil, then an error occurred while trying determine the interface address.
+ (NSString*_Nullable)getInterfaceAddress:(NSString*_Nonnull)interfaceName
                                    error:(NSError *_Nullable *_Nonnull)outError;

/// Returns list of active interfaces excluding the loopback interface which support communicating with IPv4, or IPv6, addresses.
+ (NSSet<NSString*>*)activeInterfaces:(NSError *_Nullable *_Nonnull)outError;

/// Returns the active interface name.
/// @param reachability ReachabilityProtocol implementer used to determine active interface on iOS >=12.
/// @param currentNetworkStatus Used to determine active interface on iOS <12.
/// @param outError If non-nil, then an error occurred while determining the active interface.
+ (NSString*)getActiveInterfaceWithReachability:(id<ReachabilityProtocol>)reachability
                        andCurrentNetworkStatus:(NetworkReachability)currentNetworkStatus
                                          error:(NSError *_Nullable *_Nonnull)outError;

@end

NS_ASSUME_NONNULL_END
