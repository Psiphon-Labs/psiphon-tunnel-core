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

/// Returns the BSSIDs of the current Wi-Fi network reported by CNCopyCurrentNetworkInfo, one per interface.
typedef NSArray<NSString *> *_Nonnull (^NetworkIDCurrentNetworkInfoBSSIDs)(void);

/// Returns the address of the active interface, or sets outError.
typedef NSString *_Nullable (^NetworkIDInterfaceAddress)(NSError *_Nullable *_Nonnull outError);

@interface NetworkID : NSObject

/// The network ID contains potential PII. In tunnel-core, the network ID
/// is used only locally in the client and not sent to the server.
///
/// See network ID requirements here:
/// https://godoc.org/github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon#NetworkIDGetter
///
/// On iOS and Mac Catalyst, a Wi-Fi network ID includes the BSSID, if available, or else the address of the active
/// interface. See wifiNetworkIDWithBSSID:currentNetworkInfoBSSIDs:interfaceAddress:warning:.
///
/// @param reachability ReachabilityProtocol implementer used to determine active interface on iOS >=12 when
/// the network ID includes the active interface address.
/// @param currentNetworkStatus Used to determine network ID and, on iOS <12, to determine the active interface when
/// the network ID includes the active interface address.
/// @param tunnelWholeDevice False if library is used in non-VPN mode, true otherwise.
/// @param wifiBSSID BSSID of the current Wi-Fi network from NEHotspotNetwork, or nil if unavailable. See
/// WiFiNetworkInfo. Ignored on native macOS.
/// @param outWarn If non-nil, then a non-fatal error occurred while determining the network ID and a valid network ID will still be returned.
+ (NSString *)getNetworkIDWithReachability:(id<ReachabilityProtocol>)reachability
                   andCurrentNetworkStatus:(NetworkReachability)currentNetworkStatus
                         tunnelWholeDevice:(BOOL)tunnelWholeDevice
                                 wifiBSSID:(NSString *_Nullable)wifiBSSID
                                   warning:(NSError *_Nullable *_Nonnull)outWarn;

/// Returns the Wi-Fi network ID built from the first available source:
///
/// 1. wifiBSSID, from NEHotspotNetwork: "WIFI-<BSSID>".
/// 2. The BSSIDs from CNCopyCurrentNetworkInfo: "WIFI-<BSSID>", with one suffix per interface. This API is
///    deprecated, and returns NULL to apps linked against the iOS 19 SDK or later.
/// 3. The address of the active interface: "WIFI-<address>". Different networks may share an address, and a
///    network may assign a new one, but the address distinguishes more networks than "WIFI" alone.
/// 4. "WIFI", with outWarn set to the interface address error.
///
/// Each source is queried only if the previous one yields nothing.
+ (NSString *)wifiNetworkIDWithBSSID:(NSString *_Nullable)wifiBSSID
            currentNetworkInfoBSSIDs:(NetworkIDCurrentNetworkInfoBSSIDs)currentNetworkInfoBSSIDs
                    interfaceAddress:(NetworkIDInterfaceAddress)interfaceAddress
                             warning:(NSError *_Nullable *_Nonnull)outWarn;

@end

NS_ASSUME_NONNULL_END
