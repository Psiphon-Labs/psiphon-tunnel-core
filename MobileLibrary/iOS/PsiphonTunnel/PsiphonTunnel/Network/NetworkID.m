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

#import "NetworkID.h"
#import "NetworkInterface.h"
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <CoreTelephony/CTCarrier.h>
#import <SystemConfiguration/CaptiveNetwork.h>

NSString *kNetworkIDUnknown = @"UNKNOWN";

@implementation NetworkID

/// Internal helper function. See comment in header for `getNetworkIDWithReachability:andCurrentNetworkStatus:warning:`.
/// @param networkReachability Network reachability status.
/// @param defaultActiveInterfaceName Interface associated with the default route on the device.
/// @param outWarn If non-nil, then a non-fatal error occurred while determining the network ID and a valid network ID will still be returned.
+ (NSString * _Nonnull)getNetworkID:(NetworkReachability)networkReachability
         defaultActiveInterfaceName:(NSString*)defaultActiveInterfaceName
                            warning:(NSError *_Nullable *_Nonnull)outWarn {
    *outWarn = nil;

    NSMutableString *networkID = [NSMutableString stringWithString:kNetworkIDUnknown];
    if (networkReachability == NetworkReachabilityReachableViaWiFi) {
        [networkID setString:@"WIFI"];
        NSArray *networkInterfaceNames = (__bridge_transfer id)CNCopySupportedInterfaces();
        for (NSString *networkInterfaceName in networkInterfaceNames) {
            NSDictionary *networkInterfaceInfo = (__bridge_transfer id)CNCopyCurrentNetworkInfo((__bridge CFStringRef)networkInterfaceName);
            if (networkInterfaceInfo[(__bridge NSString*)kCNNetworkInfoKeyBSSID]) {
                [networkID appendFormat:@"-%@", networkInterfaceInfo[(__bridge NSString*)kCNNetworkInfoKeyBSSID]];
            }
        }
    } else if (networkReachability == NetworkReachabilityReachableViaCellular) {
        [networkID setString:@"MOBILE"];
        CTTelephonyNetworkInfo *telephonyNetworkinfo = [[CTTelephonyNetworkInfo alloc] init];
        CTCarrier *cellularProvider = [telephonyNetworkinfo subscriberCellularProvider];
        if (cellularProvider != nil) {
            NSString *mcc = [cellularProvider mobileCountryCode];
            NSString *mnc = [cellularProvider mobileNetworkCode];
            [networkID appendFormat:@"-%@-%@", mcc, mnc];
        }
    } else if (networkReachability == NetworkReachabilityReachableViaWired) {
        [networkID setString:@"WIRED"];
        if (defaultActiveInterfaceName != NULL) {
            NSError *err;
            NSString *interfaceAddress = [NetworkInterface getInterfaceAddress:defaultActiveInterfaceName
                                                                         error:&err];
            if (err != nil) {
                NSString *localizedDescription =
                    [NSString stringWithFormat:@"getNetworkID: error getting interface address %@", err.localizedDescription];
                *outWarn = [[NSError alloc] initWithDomain:@"iOSLibrary" code:1 userInfo:@{NSLocalizedDescriptionKey: localizedDescription}];
                return networkID;
            } else if (interfaceAddress != nil) {
                [networkID appendFormat:@"-%@", interfaceAddress];
            }
        }
    } else if (networkReachability == NetworkReachabilityReachableViaLoopback) {
        [networkID setString:@"LOOPBACK"];
    }
    return networkID;
}

// See comment in header.
+ (NSString *)getNetworkIDWithReachability:(id<ReachabilityProtocol>)reachability
                   andCurrentNetworkStatus:(NetworkReachability)currentNetworkStatus
                                   warning:(NSError *_Nullable *_Nonnull)outWarn {
    *outWarn = nil;

    NSError *err;
    NSString *activeInterface =
        [NetworkInterface getActiveInterfaceWithReachability:reachability
                                     andCurrentNetworkStatus:currentNetworkStatus
                                                       error:&err];
    if (err != nil) {
        NSString *localizedDescription = [NSString stringWithFormat:@"error getting active interface %@", err.localizedDescription];
        *outWarn = [[NSError alloc] initWithDomain:@"iOSLibrary"
                                              code:1
                                          userInfo:@{NSLocalizedDescriptionKey:localizedDescription}];
        return kNetworkIDUnknown;
    }

    NSError *warn;
    NSString *networkID = [NetworkID getNetworkID:currentNetworkStatus
                       defaultActiveInterfaceName:activeInterface
                                          warning:&warn];
    if (warn != nil) {
        NSString *localizedDescription = [NSString stringWithFormat:@"error getting network ID: %@", warn.localizedDescription];
        *outWarn = [[NSError alloc] initWithDomain:@"iOSLibrary"
                                              code:1
                                          userInfo:@{NSLocalizedDescriptionKey:localizedDescription}];
    }

    return networkID;
}

@end
