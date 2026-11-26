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
#import <Network/Network.h>
#import <ifaddrs.h>
#import <netinet/in.h>
#import "ReachabilityProtocol.h"

NS_ASSUME_NONNULL_BEGIN

@class NetworkPathState;

/// Selects the address of the named interface from a getifaddrs(3) list. Only up, non-loopback interfaces with
/// an IPv4 or IPv6 address are considered.
///
/// The first IPv4 address is selected if there is one, skipping link-local addresses and addresses in
/// 192.0.0.0/29 (RFC 7335): 464XLAT assigns the same address, typically 192.0.0.2, on every IPv6-only network
/// that provides IPv4 by translation, so it does not identify the network.
///
/// Otherwise an IPv6 address is selected for its first 32 bits, which are all that the network ID uses (see
/// NetworkInterfaceFormatIPv6Prefix). Only unique local (fc00::/7) and global unicast (2000::/3) addresses are
/// considered. Unique local is preferred over global, and within the preferred class the address whose first 32
/// bits are numerically lowest is selected. Full IPv6 addresses change with the delegated prefix and with privacy
/// address rotation, so the network ID trades precision for stability: two networks may share an ID, but one
/// network should keep its ID. This does not guarantee a stable or unique network ID.
///
/// @param interfaces getifaddrs(3) list. May be NULL.
/// @param interfaceName Interface name. E.g. "en0".
/// @return The selected list entry, or NULL if no address qualifies.
const struct ifaddrs *_Nullable NetworkInterfaceSelectAddress(const struct ifaddrs *_Nullable interfaces,
                                                              const char *_Nullable interfaceName);

/// Returns the first 32 bits of the IPv6 address as a /32 prefix: the two leading 16-bit groups in lowercase
/// hexadecimal without leading zeros, followed by "::/32". E.g. 2001:db8:85a3::1 gives "2001:db8::/32".
NSString *NetworkInterfaceFormatIPv6Prefix(const struct in6_addr *addr);

/// NetworkInterface provides a set of functions for discovering active network interfaces on the device.
@interface NetworkInterface : NSObject

/// Returns the network ID value of the given interface, chosen with NetworkInterfaceSelectAddress: the full
/// address if an IPv4 address is selected, or the /32 prefix formatted by NetworkInterfaceFormatIPv6Prefix if an
/// IPv6 address is selected. If no address qualifies, then nil is returned.
/// @param interfaceName Interface name. E.g. "en0".
/// @param outError If non-nil, then an error occurred while trying determine the interface address.
+ (NSString*_Nullable)getInterfaceAddress:(NSString*_Nonnull)interfaceName
                                    error:(NSError *_Nullable *_Nonnull)outError;

/// Returns list of active interfaces excluding the loopback interface which support communicating with IPv4, or IPv6, addresses.
+ (NSSet<NSString*>*)activeInterfaces:(NSError *_Nullable *_Nonnull)outError;

/// Returns the active interface name.
/// @param pathState DefaultRouteMonitor path state whose defaultActiveInterfaceName is the active interface on
/// iOS >=12. If nil on iOS >=12, then an error is returned.
/// @param currentNetworkStatus Used to determine active interface on iOS <12.
/// @param outError If non-nil, then an error occurred while determining the active interface.
+ (NSString*)getActiveInterfaceWithPathState:(NetworkPathState *_Nullable)pathState
                     andCurrentNetworkStatus:(NetworkReachability)currentNetworkStatus
                                       error:(NSError *_Nullable *_Nonnull)outError;
/// Returns getInterfaceAddress for the active interface: an IPv4 address or an IPv6 /32 prefix.
/// @param pathState DefaultRouteMonitor path state whose defaultActiveInterfaceName is the active interface on
/// iOS >=12. If nil on iOS >=12, then an error is returned.
/// @param currentNetworkStatus Used to determine active interface on iOS <12.
/// @param outError If non-nil, then an error occurred while determining the active interface.
+ (NSString*)getActiveInterfaceAddressWithPathState:(NetworkPathState *_Nullable)pathState
                            andCurrentNetworkStatus:(NetworkReachability)currentNetworkStatus
                                              error:(NSError *_Nullable *_Nonnull)outError;

@end

NS_ASSUME_NONNULL_END
